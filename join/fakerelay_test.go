package join

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// defaultRelayVersion is what a relay announces when its knobs name no
// version: a release that sends the no-host banner, so a refusal at
// authentication is definitive.
const defaultRelayVersion = "SSH-2.0-uptermd-0.37.0"

// handshakeTimeout bounds a fixture's handshake, so a stalled one fails its
// test instead of hanging the run.
const handshakeTimeout = 10 * time.Second

// errFixtureRefused is how the fixture relay turns a key away.
var errFixtureRefused = errors.New("fixture relay: key refused")

// relayKnobs is one connection's behaviour, on an x/crypto server over
// loopback TCP (both SSH ends write their version line before reading, so an
// unbuffered net.Pipe deadlocks; x/crypto's own tests use TCP for this).
// Zero means: accept any key, no banner, version "SSH-2.0-uptermd-0.37.0" (a
// release, so refusals at authentication are definitive), accept the session
// channel.
type relayKnobs struct {
	refuseAll       bool          // every publickey query fails
	allow           ssh.PublicKey // accept only this key (nil: any)
	dropOnPublicKey bool          // close the conn once a publickey request arrives
	maxAuthTries    int
	banner          string // sent with each refusal
	version         string
	pubKeyAlgos     []string
	rejectSession   string // reject "session" with ConnectionFailed and this message
}

// serve runs the relay's end of one connection until it closes. It is the one
// place that end is written, so a behaviour the fixture learns lands here.
func (k relayKnobs) serve(conn net.Conn, hostKey ssh.Signer) {
	defer func() { _ = conn.Close() }()

	cfg := &ssh.ServerConfig{
		ServerVersion:           cmp.Or(k.version, defaultRelayVersion),
		MaxAuthTries:            k.maxAuthTries,
		PublicKeyAuthAlgorithms: k.pubKeyAlgos,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if k.dropOnPublicKey {
				_ = conn.Close()
				return nil, errFixtureRefused
			}
			if k.refuseAll || (k.allow != nil && !bytes.Equal(key.Marshal(), k.allow.Marshal())) {
				return nil, k.refusal()
			}
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(hostKey)

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		// A guest turned away or dropped is what the test is about; the client
		// side reports it.
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)

	k.channels(chans)
}

// refusal is the error the relay's key callback returns: carrying the banner,
// as the real relay's does, when the knobs name one.
func (k relayKnobs) refusal() error {
	if k.banner == "" {
		return errFixtureRefused
	}
	return &ssh.BannerError{Err: errFixtureRefused, Message: k.banner}
}

// channels answers the channels a guest opens until the connection closes.
func (k relayKnobs) channels(chans <-chan ssh.NewChannel) {
	for nc := range chans {
		switch {
		case nc.ChannelType() != "session":
			_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
		case k.rejectSession != "":
			_ = nc.Reject(ssh.ConnectionFailed, k.rejectSession)
		default:
			// The session stays open, and silent, until the connection closes.
			_, reqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
		}
	}
}

// listen serves each connection to a loopback listener with k and returns the
// listener's address. The test's cleanup closes the listener and every
// connection it accepted, and waits for their goroutines.
func (k relayKnobs) listen(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	hostKey := newSigner(t)

	var (
		mu     sync.Mutex
		closed bool
		conns  []net.Conn
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			conns = append(conns, conn)
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				k.serve(conn, hostKey)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		closed = true
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}

// open dials the relay k describes and runs the handshake as an attempt does,
// with clientConfig, and returns the client if it succeeded, the evidence the
// handshake left and the handshake's error.
func (k relayKnobs) open(t *testing.T, signers []ssh.Signer, checkHostKey ssh.HostKeyCallback) (*ssh.Client, *evidence, error) {
	t.Helper()

	addr := k.listen(t)
	nc, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = nc.Close() })

	ev := &evidence{}
	require.NoError(t, nc.SetDeadline(time.Now().Add(handshakeTimeout)))
	conn, chans, reqs, err := ssh.NewClientConn(nc, addr, clientConfig("abc", signers, checkHostKey, ev))
	if err != nil {
		return nil, ev, err
	}
	require.NoError(t, nc.SetDeadline(time.Time{}))
	return ssh.NewClient(conn, chans, reqs), ev, nil
}

// connect runs ssh.NewClientConn with track, an AuthCallback and a
// BannerCallback exactly as an attempt does, accepting the relay's host key,
// and returns the evidence and the handshake error.
func connect(t *testing.T, k relayKnobs, signers []ssh.Signer) (*evidence, error) {
	t.Helper()
	_, ev, err := k.open(t, signers, ssh.InsecureIgnoreHostKey())
	return ev, err
}

// dial is connect that requires success and returns the client.
func (k relayKnobs) dial(t *testing.T, signers []ssh.Signer) *ssh.Client {
	t.Helper()
	client, _, err := k.open(t, signers, ssh.InsecureIgnoreHostKey())
	require.NoError(t, err)
	return client
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func newRSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func oneSigner(t *testing.T) []ssh.Signer {
	t.Helper()
	return []ssh.Signer{newSigner(t)}
}

func sevenSigners(t *testing.T) []ssh.Signer {
	t.Helper()
	signers := make([]ssh.Signer, 7)
	for i := range signers {
		signers[i] = newSigner(t)
	}
	return signers
}

// failingSigner is a signer whose Sign fails, as an agent's does once it is
// gone.
type failingSigner struct{ ssh.Signer }

func (failingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("the agent is gone")
}

// stripErr is v with its error cleared, for comparing the rest.
func stripErr(v verdict) verdict {
	v.err = nil
	return v
}
