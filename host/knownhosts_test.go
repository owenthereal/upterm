package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var fakeAddr = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 22}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(mustGenerateEd25519(t))
	require.NoError(t, err)
	return signer
}

func writeKnownHosts(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))
	return file
}

func signHostCert(t *testing.T, ca ssh.Signer, key ssh.PublicKey, principal string) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             key,
		CertType:        ssh.HostCert,
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	return cert
}

func TestCheckTrustsACertAuthorityLine(t *testing.T) {
	ca, hostKey := newSigner(t), newSigner(t)
	cert := signHostCert(t, ca, hostKey.PublicKey(), "relay.test")
	file := writeKnownHosts(t, "@cert-authority relay.test "+string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	require.NoError(t, KnownHosts{File: file}.Check("relay.test:22", fakeAddr, cert))
}

func TestCheckReportsUnknownAndChangedKeys(t *testing.T) {
	a, b := newSigner(t).PublicKey(), newSigner(t).PublicKey()
	require.ErrorIs(t, KnownHosts{File: writeKnownHosts(t, "")}.Check("relay.test:22", fakeAddr, a), ErrUnknownHostKey)

	pinned := writeKnownHosts(t, knownhosts.Line([]string{"relay.test"}, a)+"\n")
	require.NoError(t, KnownHosts{File: pinned}.Check("relay.test:22", fakeAddr, a))
	err := KnownHosts{File: pinned}.Check("relay.test:22", fakeAddr, b)
	require.ErrorIs(t, err, ErrHostKeyChanged)
	require.Contains(t, err.Error(), "REMOTE HOST IDENTIFICATION HAS CHANGED")
}

func TestAMissingKnownHostsIsAnEmptyTrustStore(t *testing.T) {
	file := filepath.Join(t.TempDir(), "no-ssh-dir", ".ssh", "known_hosts")
	key := newSigner(t).PublicKey()
	kh := KnownHosts{File: file, Stdout: io.Discard}
	require.ErrorIs(t, kh.Check("relay.test:22", fakeAddr, key), ErrUnknownHostKey)
	ok, err := kh.Confirm(context.Background(), strings.NewReader("yes\n"), "relay.test:22", fakeAddr, key)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, kh.Check("relay.test:22", fakeAddr, key))
	if runtime.GOOS != "windows" { // Windows reports every directory as 0777
		info, err := os.Stat(filepath.Dir(file))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
}

// signalOnRead closes entered on its first Read.
type signalOnRead struct {
	r       io.Reader
	entered chan struct{}
	once    sync.Once
}

func (s *signalOnRead) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.r.Read(p)
}

func TestConfirmReturnsAtOnceWhenCancelled(t *testing.T) {
	never, release := io.Pipe() // a read that never returns, until the test ends
	t.Cleanup(func() { _ = release.Close() })
	in := &signalOnRead{r: never, entered: make(chan struct{})}
	kh := KnownHosts{File: writeKnownHosts(t, ""), Stdout: io.Discard}
	key := newSigner(t).PublicKey()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := kh.Confirm(ctx, in, "relay.test:22", fakeAddr, key)
		done <- err
	}()
	// Cancel only once Confirm is blocked in the read, so that nothing but its
	// wait on ctx can return it.
	select {
	case <-in.entered:
	case <-time.After(time.Second):
		t.Fatal("Confirm did not read the answer")
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Confirm did not return when its ctx ended")
	}
}

func TestConfirmLeavesWhatFollowsTheAnswerUnread(t *testing.T) {
	r := strings.NewReader("yes\nAFTER")
	ok, err := KnownHosts{File: writeKnownHosts(t, ""), Stdout: io.Discard}.
		Confirm(context.Background(), r, "relay.test:22", fakeAddr, newSigner(t).PublicKey())
	require.NoError(t, err)
	require.True(t, ok)
	rest, _ := io.ReadAll(r)
	require.Equal(t, "AFTER", string(rest))
}

func TestConfirmRecordsOnYesAndFingerprintAndNotOnNo(t *testing.T) {
	key := newSigner(t).PublicKey()
	for answer, want := range map[string]bool{
		"yes\n": true, utils.FingerprintSHA256(key) + "\n": true, "no\n": false,
	} {
		file := writeKnownHosts(t, "")
		ok, err := KnownHosts{File: file, Stdout: io.Discard}.
			Confirm(context.Background(), strings.NewReader(answer), "relay.test:22", fakeAddr, key)
		require.NoError(t, err, answer)
		require.Equal(t, want, ok, answer)
		check := KnownHosts{File: file}.Check("relay.test:22", fakeAddr, key)
		if want {
			require.NoError(t, check, answer)
		} else {
			require.ErrorIs(t, check, ErrUnknownHostKey, answer)
		}
	}
}

func TestConfirmAsksAgainUntilItIsAnswered(t *testing.T) {
	var out bytes.Buffer
	ok, err := KnownHosts{File: writeKnownHosts(t, ""), Stdout: &out}.
		Confirm(context.Background(), strings.NewReader("maybe\n\nno\n"), "relay.test:22", fakeAddr, newSigner(t).PublicKey())
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, 2, strings.Count(out.String(), "Please type 'yes', 'no' or the fingerprint: "))
}

// readCounter counts the reads made of it.
type readCounter struct {
	r io.Reader
	n atomic.Int32
}

func (c *readCounter) Read(p []byte) (int, error) {
	c.n.Add(1)
	return c.r.Read(p)
}

func TestConfirmDoesNothingWhenItsContextIsAlreadyDone(t *testing.T) {
	in := &readCounter{r: strings.NewReader("yes\n")}
	var out bytes.Buffer
	file := writeKnownHosts(t, "")
	key := newSigner(t).PublicKey()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ok, err := KnownHosts{File: file, Stdout: &out}.Confirm(ctx, in, "relay.test:22", fakeAddr, key)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, ok)
	require.Empty(t, out.String(), "no prompt")
	require.Zero(t, in.n.Load(), "no read")
	require.ErrorIs(t, KnownHosts{File: file}.Check("relay.test:22", fakeAddr, key), ErrUnknownHostKey)
}

// signalOnNewline closes signal when it hands over a newline.
type signalOnNewline struct {
	r      io.Reader
	signal chan struct{}
	once   sync.Once
}

func (s *signalOnNewline) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if bytes.IndexByte(p[:n], '\n') >= 0 {
		s.once.Do(func() { close(s.signal) })
	}
	return n, err
}

// endsAfterAnswer is a context that is live until it is asked to wait on
// Done, which it does only once the answer has been handed over, and then
// reports itself ended with the answer ready to be received as well.
type endsAfterAnswer struct {
	context.Context
	answered <-chan struct{}
	ended    atomic.Bool
}

func (c *endsAfterAnswer) Done() <-chan struct{} {
	select {
	case <-c.answered:
	case <-time.After(5 * time.Second):
	}
	// Time for Confirm's reader to send what it read. Too short a wait can only
	// make the test pass when it should fail, never fail when it should pass.
	time.Sleep(10 * time.Millisecond)
	c.ended.Store(true)
	done := make(chan struct{})
	close(done)
	return done
}

func (c *endsAfterAnswer) Err() error {
	if c.ended.Load() {
		return context.Canceled
	}
	return nil
}

func TestConfirmRecordsNothingWhenItsContextEndsWithTheAnswerReady(t *testing.T) {
	key := newSigner(t).PublicKey()
	for range 30 { // with both ready, select picks either at random
		file := writeKnownHosts(t, "")
		answered := make(chan struct{})
		in := &signalOnNewline{r: strings.NewReader("yes\n"), signal: answered}
		ctx := &endsAfterAnswer{Context: context.Background(), answered: answered}

		ok, err := KnownHosts{File: file, Stdout: io.Discard}.Confirm(ctx, in, "relay.test:22", fakeAddr, key)
		require.ErrorIs(t, err, context.Canceled)
		require.False(t, ok)
		require.ErrorIs(t, KnownHosts{File: file}.Check("relay.test:22", fakeAddr, key), ErrUnknownHostKey)
	}
}

func TestCheckReturnsARevokedKeyAsKnownhostsDoes(t *testing.T) {
	key := newSigner(t).PublicKey()
	file := writeKnownHosts(t, "@revoked * "+string(ssh.MarshalAuthorizedKey(key)))
	err := KnownHosts{File: file}.Check("relay.test:22", fakeAddr, key)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrUnknownHostKey)
	require.NotErrorIs(t, err, ErrHostKeyChanged)
	var revoked *knownhosts.RevokedError
	require.ErrorAs(t, err, &revoked)
}

func TestRecordStartsANewLineAfterOneThatHasNone(t *testing.T) {
	a, b := newSigner(t).PublicKey(), newSigner(t).PublicKey()
	first := knownhosts.Line([]string{"first.test"}, a)
	second := knownhosts.Line([]string{"second.test"}, b)
	for name, tc := range map[string]struct{ existing, want string }{
		"no newline at the end": {first, first + "\n" + second + "\n"},
		"newline at the end":    {first + "\n", first + "\n" + second + "\n"},
		"empty":                 {"", second + "\n"},
	} {
		file := writeKnownHosts(t, tc.existing)
		kh := KnownHosts{File: file, Stdout: io.Discard}
		require.NoError(t, kh.Record("second.test:22", b, false), name)

		got, err := os.ReadFile(file)
		require.NoError(t, err, name)
		require.Equal(t, tc.want, string(got), name)
		if tc.existing != "" {
			require.NoError(t, kh.Check("first.test:22", fakeAddr, a), name)
		}
		require.NoError(t, kh.Check("second.test:22", fakeAddr, b), name)
	}
}
