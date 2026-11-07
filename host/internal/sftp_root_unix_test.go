//go:build !windows

package internal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/owenthereal/upterm/server"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRootedSFTPWaitIncludesBlockedWorkers(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer close(release)
	srv := &Server{Command: readsALine("READY", 0), SFTPRoot: root, PermissionChecker: sftpConsentChecker{check: func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release // deliberately prove a checker that ignores cancellation is not joined
		return consent.AllowConnection, nil
	}}}
	h := startHost(t, srv)
	client, err := sftp.NewClient(h.guestClient(t))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	opened := make(chan error, 1)
	go func() {
		f, err := client.Create("pending")
		if f != nil {
			_ = f.Close()
		}
		opened <- err
	}()
	select {
	case <-entered:
	case <-time.After(harnessTimeout):
		t.Fatal("permission worker never started")
	}
	h.stop(t)
	select {
	case <-canceled:
	case <-time.After(harnessTimeout):
		t.Fatal("rooted request was not canceled")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, srv.WaitSFTP(ctx), context.DeadlineExceeded, "returning from Serve is not a worker join")
	_, err = root.Stat(".")
	require.NoError(t, err, "server closed the caller-owned root")
	// A separate sender releases the checker without closing release twice.
	release <- struct{}{}
	joined, cancelJoin := context.WithTimeout(t.Context(), harnessTimeout)
	defer cancelJoin()
	require.NoError(t, srv.WaitSFTP(joined))
	require.Error(t, <-opened)
	_, err = root.Stat("pending")
	require.True(t, os.IsNotExist(err), "a late permission grant created a file after cancellation")
}

func TestRootedSFTPTrustsRelayIdentityButConfinesItsAccess(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	guestKey, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPRoot: root, SFTPAutoAccept: true, AuthorizedKeys: []ssh.PublicKey{guestKey}})
	// The relay can attest an allowed guest key without possessing its private
	// key. This is the threat the filesystem boundary must still contain.
	h.guestSigner, err = (&server.UserCertSigner{User: "guest", SessionID: t.Name(), AuthRequest: &server.AuthRequest{AuthorizedKey: ssh.MarshalAuthorizedKey(guestKey)}}).SignCert(h.relaySigner)
	require.NoError(t, err)
	client, err := sftp.NewClient(h.guestClient(t))
	require.NoError(t, err)
	defer func() { _ = client.Close() }()
	outside := filepath.Join(t.TempDir(), "private")
	require.NoError(t, os.WriteFile(outside, []byte("private"), 0600))
	_, err = client.Open(outside)
	require.Error(t, err)
	_, err = client.Stat(outside)
	require.Error(t, err)
	h.stop(t)
	require.NoError(t, h.srv.WaitSFTP(t.Context()))
}

func TestNilRootSFTPKeepsAbsoluteAccessAndConsent(t *testing.T) {
	file := filepath.Join(t.TempDir(), "existing")
	require.NoError(t, os.WriteFile(file, []byte("ordinary"), 0600))
	for _, accepted := range []bool{false, true} {
		h := startHost(t, &Server{Command: readsALine("READY", 0), SFTPAutoAccept: accepted})
		client, err := sftp.NewClient(h.guestClient(t))
		require.NoError(t, err)
		f, err := client.Open(file)
		if accepted {
			require.NoError(t, err)
			require.NoError(t, f.Close())
		} else {
			require.Error(t, err)
		}
		_, err = client.Stat(file)
		require.NoError(t, err, "nil root preserves existing metadata semantics")
		require.NoError(t, client.Close())
		h.stop(t)
	}
}
