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
	"sync/atomic"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/upterm"
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
// channel, its pty and its shell, and then keep the session open, quiet, and
// answering keepalives, until the connection closes.
type relayKnobs struct {
	refuseAll       bool          // every publickey query fails
	allow           ssh.PublicKey // accept only this key (nil: any)
	dropOnPublicKey bool          // close the conn once a publickey request arrives
	maxAuthTries    int
	banner          string // sent with each refusal
	version         string
	pubKeyAlgos     []string
	rejectSession   string // reject "session" with ConnectionFailed and this message

	// What a join's CheckHostKey says about this connection's relay key; the
	// fixture's config reads them.
	hostKeyUnknown, hostKeyChanged bool
	// stallHandshake never sends the relay's version line.
	stallHandshake bool
	// acceptUpstreamOnly rejects "session" unless the guest authenticated with
	// this key (nil: no such check), as the session's node does when the entry
	// node let a key in that the host doesn't authorize. The rejection is the
	// ambiguous UpstreamAuthFailed of a node that predates the refined
	// verdicts, or, with confirmRefusal, UpstreamKeyRefused.
	acceptUpstreamOnly ssh.PublicKey
	confirmRefusal     bool
	// setupFails rejects the pty request.
	setupFails bool
	// output is written once the shell starts.
	output string
	// exit, after output, sends this exit status and closes the session.
	exit *int
	// dropAfterReady, after output, closes the connection without a status.
	dropAfterReady bool
	// silentAfterReady, after output, stops sending anything, keepalive
	// replies included.
	silentAfterReady bool
}

// connLog is what the relay saw on one connection.
type connLog struct {
	mu    sync.Mutex
	key   ssh.PublicKey   // the key that authenticated
	ptys  []termsize.Size // the size of each pty request
	input bytes.Buffer    // what the session received
}

func (l *connLog) setKey(k ssh.PublicKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.key = k
}

func (l *connLog) pty(s termsize.Size) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ptys = append(l.ptys, s)
}

func (l *connLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.input.Write(p)
}

// permKey is the Permissions extension the relay keeps the authenticated key
// in, so that it knows which key got in once the handshake is over.
const permKey = "fixture-key"

// serve runs the relay's end of one connection until it closes, noting in seen
// what it saw. It is the one place that end is written, so a behaviour the
// fixture learns lands here.
func (k relayKnobs) serve(conn net.Conn, hostKey ssh.Signer, seen *connLog) {
	defer func() { _ = conn.Close() }()

	if k.stallHandshake {
		// A relay that took the connection and then stopped: it reads what the
		// guest sends and never answers, until the guest gives up.
		_, _ = io.Copy(io.Discard, conn)
		return
	}

	cfg := &ssh.ServerConfig{
		ServerVersion:           cmp.Or(k.version, defaultRelayVersion),
		MaxAuthTries:            k.maxAuthTries,
		PublicKeyAuthAlgorithms: k.pubKeyAlgos,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if k.dropOnPublicKey {
				_ = conn.Close()
				return nil, errFixtureRefused
			}
			if k.refuseAll || (k.allow != nil && !sameKey(key, k.allow)) {
				return nil, k.refusal()
			}
			return &ssh.Permissions{Extensions: map[string]string{permKey: string(key.Marshal())}}, nil
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
	key, err := ssh.ParsePublicKey([]byte(sconn.Permissions.Extensions[permKey]))
	if err == nil {
		seen.setKey(key)
	}

	// The connection's global requests are the guest's keepalives: answered,
	// as the relay forwards them to a host that answers, until silent.
	var silent atomic.Bool
	go func() {
		for req := range reqs {
			if req.WantReply && !silent.Load() {
				_ = req.Reply(false, nil)
			}
		}
	}()

	k.channels(chans, sconn, key, &silent, seen)
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
func (k relayKnobs) channels(chans <-chan ssh.NewChannel, sconn *ssh.ServerConn, key ssh.PublicKey, silent *atomic.Bool, seen *connLog) {
	for nc := range chans {
		switch {
		case nc.ChannelType() != "session":
			_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
		case k.rejectSession != "":
			_ = nc.Reject(ssh.ConnectionFailed, k.rejectSession)
		case k.acceptUpstreamOnly != nil && (key == nil || !sameKey(key, k.acceptUpstreamOnly)):
			msg := upterm.UpstreamAuthFailed
			if k.confirmRefusal {
				msg = upterm.UpstreamKeyRefused
			}
			_ = nc.Reject(ssh.ConnectionFailed, msg)
		default:
			ch, reqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go k.session(ch, reqs, sconn, silent, seen)
		}
	}
}

// session answers one session's requests: its pty, which it notes, and its
// shell, which starts the script the knobs describe.
func (k relayKnobs) session(ch ssh.Channel, reqs <-chan *ssh.Request, sconn *ssh.ServerConn, silent *atomic.Bool, seen *connLog) {
	go func() { _, _ = io.Copy(seen, ch) }()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var pty struct {
				Term                      string
				Cols, Rows, Width, Height uint32
				Modes                     string
			}
			if err := ssh.Unmarshal(req.Payload, &pty); err == nil {
				seen.pty(termsize.Size{Cols: int(pty.Cols), Rows: int(pty.Rows)})
			}
			_ = req.Reply(!k.setupFails, nil)
		case "shell":
			_ = req.Reply(true, nil)
			go k.script(ch, sconn, silent)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// script is what the session does once its shell has started.
func (k relayKnobs) script(ch ssh.Channel, sconn *ssh.ServerConn, silent *atomic.Bool) {
	if k.output != "" {
		_, _ = ch.Write([]byte(k.output))
	}
	switch {
	case k.exit != nil:
		status := struct{ Status uint32 }{uint32(*k.exit)}
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
		_ = ch.Close()
	case k.dropAfterReady:
		_ = sconn.Close()
	case k.silentAfterReady:
		silent.Store(true)
	}
}

func sameKey(a, b ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), b.Marshal()) }

// listen serves each connection to a loopback listener with serve, which is
// told the connection's index in the order they were accepted, and returns
// the listener's address. The test's cleanup closes the listener and every
// connection it accepted, and waits for their goroutines.
func listen(t *testing.T, serve func(i int, conn net.Conn)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu     sync.Mutex
		closed bool
		conns  []net.Conn
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
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
				serve(i, conn)
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

	hostKey := newSigner(t)
	addr := listen(t, func(_ int, conn net.Conn) { k.serve(conn, hostKey, &connLog{}) })
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
