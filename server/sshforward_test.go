package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// These endpoints use only the stock connection API, including reverse opens.
func forwardTestPair(t *testing.T, serverConfig *ssh.ServerConfig, clientConfig *ssh.ClientConfig) (sshPeer, sshPeer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig == nil {
		serverConfig = &ssh.ServerConfig{NoClientAuth: true}
	}
	serverConfig.AddHostKey(signer)
	if clientConfig == nil {
		clientConfig = &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	type result struct {
		peer sshPeer
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		sc, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			accepted <- result{err: err}
			return
		}
		// The deadline bounds the handshake, not the test. Left armed it
		// expires mid-test on anything that runs longer, breaking the transport
		// in a way that reads as the failure the test was looking for. Clearing
		// it here is what sshstock.go does after its own handshake; the tests
		// carry their own explicit bounds.
		_ = conn.SetDeadline(time.Time{})
		accepted <- result{peer: sshPeer{sc, channels, requests}}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cc, channels, requests, err := ssh.NewClientConn(conn, listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	server := <-accepted
	if server.err != nil {
		t.Fatal(server.err)
	}
	client := sshPeer{cc, channels, requests}
	t.Cleanup(func() {
		_ = client.conn.Close()
		_ = server.peer.conn.Close()
		waited := make(chan struct{})
		go func() { _ = client.conn.Wait(); _ = server.peer.conn.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(time.Second):
			t.Error("SSH mux did not finish after transport close")
		}
	})
	return client, server.peer
}

func forwardTestProxy(t *testing.T) (sshPeer, sshPeer, context.CancelFunc, <-chan error) {
	t.Helper()
	client, downstream := forwardTestPair(t, nil, nil)
	upstream, server := forwardTestPair(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		done <- forwardSSH(ctx, downstream, upstream, abortConnection, discardLogger())
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Error("forwarder workers did not drain")
		}
	})
	return client, server, cancel, done
}

func forwardTestReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value, ok := <-ch:
		if !ok {
			t.Fatal("unexpected closed channel")
		}
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SSH message")
	}
	var zero T
	return zero
}

func forwardTestChannel(t *testing.T, origin, destination sshPeer) (ssh.Channel, <-chan *ssh.Request, ssh.Channel, <-chan *ssh.Request) {
	t.Helper()
	type result struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	opened := make(chan result, 1)
	go func() {
		ch, reqs, err := origin.conn.OpenChannel("opaque@upterm.test", []byte{0, 1, 255})
		opened <- result{ch, reqs, err}
	}()
	incoming := forwardTestReceive(t, destination.channels)
	if incoming.ChannelType() != "opaque@upterm.test" || !bytes.Equal(incoming.ExtraData(), []byte{0, 1, 255}) {
		t.Fatalf("changed channel open: %q %v", incoming.ChannelType(), incoming.ExtraData())
	}
	ch, reqs, err := incoming.Accept()
	if err != nil {
		t.Fatal(err)
	}
	out := forwardTestReceive(t, opened)
	if out.err != nil {
		t.Fatal(out.err)
	}
	t.Cleanup(func() { _ = out.ch.Close(); _ = ch.Close() })
	return out.ch, out.reqs, ch, reqs
}

func TestSSHForwardOpaqueChannelsAndRejections(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	for _, direction := range []struct {
		name         string
		origin, dest sshPeer
	}{{"downstream", client, server}, {"upstream", server, client}} {
		t.Run(direction.name, func(t *testing.T) {
			a, ar, b, br := forwardTestChannel(t, direction.origin, direction.dest)
			go ssh.DiscardRequests(ar)
			go ssh.DiscardRequests(br)
			_ = a.Close()
			_ = b.Close()
			for _, reason := range []ssh.RejectionReason{ssh.Prohibited, ssh.ConnectionFailed, ssh.UnknownChannelType, ssh.ResourceShortage} {
				result := make(chan error, 1)
				go func() { _, _, err := direction.origin.conn.OpenChannel("rejected", []byte("extra")); result <- err }()
				incoming := forwardTestReceive(t, direction.dest.channels)
				if err := incoming.Reject(reason, "host policy explanation"); err != nil {
					t.Fatal(err)
				}
				err := forwardTestReceive(t, result)
				var rejection *ssh.OpenChannelError
				if !errors.As(err, &rejection) || rejection.Reason != reason || rejection.Message != "host policy explanation" {
					t.Fatalf("rejection changed: %v", err)
				}
			}
		})
	}
}

// The unanswered first request must hold back a later no-reply request. This
// catches a goroutine-per-request forwarder even with x/crypto's reply mutex.
func forwardTestRequests(t *testing.T, sender sshRequestSender, requests <-chan *ssh.Request, global bool) {
	t.Helper()
	type reply struct {
		ok      bool
		payload []byte
		err     error
	}
	first := make(chan reply, 1)
	go func() {
		ok, payload, err := sender.SendRequest("first@upterm.test", true, []byte{1, 0, 255})
		first <- reply{ok, payload, err}
	}()
	req := forwardTestReceive(t, requests)
	if req.Type != "first@upterm.test" || !req.WantReply || !bytes.Equal(req.Payload, []byte{1, 0, 255}) {
		t.Fatalf("changed request: %+v", req)
	}
	if _, _, err := sender.SendRequest("second@upterm.test", false, []byte("two")); err != nil {
		t.Fatal(err)
	}
	// Exceed the mux's input buffer while the first reply is still pending.
	for i := range 40 {
		if _, _, err := sender.SendRequest(fmt.Sprintf("opaque-%d", i), false, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case early := <-requests:
		t.Fatalf("request overtook unanswered predecessor: %v", early)
	case <-time.After(30 * time.Millisecond):
	}
	if err := req.Reply(true, []byte("reply payload")); err != nil {
		t.Fatal(err)
	}
	response := forwardTestReceive(t, first)
	if response.err != nil || !response.ok {
		t.Fatalf("reply failed: %+v", response)
	}
	if global && string(response.payload) != "reply payload" {
		t.Fatalf("lost global reply payload: %q", response.payload)
	}
	req = forwardTestReceive(t, requests)
	if req.Type != "second@upterm.test" || req.WantReply || string(req.Payload) != "two" {
		t.Fatalf("changed no-reply request: %+v", req)
	}
	for i := range 40 {
		req := forwardTestReceive(t, requests)
		if req.Type != fmt.Sprintf("opaque-%d", i) || req.WantReply || !bytes.Equal(req.Payload, []byte{byte(i)}) {
			t.Fatalf("request %d changed: %+v", i, req)
		}
	}
	go func() { ok, payload, err := sender.SendRequest("denied", true, nil); first <- reply{ok, payload, err} }()
	req = forwardTestReceive(t, requests)
	if err := req.Reply(false, nil); err != nil {
		t.Fatal(err)
	}
	response = forwardTestReceive(t, first)
	if response.err != nil || response.ok {
		t.Fatalf("negative reply changed: %+v", response)
	}
}

func TestSSHForwardSerialRequestsBothDirections(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	forwardTestRequests(t, client.conn, server.requests, true)
	forwardTestRequests(t, server.conn, client.requests, true)
	a, ar, b, br := forwardTestChannel(t, client, server)
	forwardTestRequests(t, sshChannelRequestSender{a}, br, false)
	forwardTestRequests(t, sshChannelRequestSender{b}, ar, false)
}

func TestSSHForwardHalfCloseStreamsAndExitStatus(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	a, ar, b, br := forwardTestChannel(t, client, server)
	go ssh.DiscardRequests(br)
	hostDone := make(chan error, 1)
	statusAllowed := make(chan struct{})
	allowStatus := sync.OnceFunc(func() { close(statusAllowed) })
	t.Cleanup(allowStatus)
	output := bytes.Repeat([]byte("stdout after EOF\n"), 8192)
	stderr := bytes.Repeat([]byte("separate stderr\n"), 8192)
	go func() {
		input, err := io.ReadAll(b)
		if err != nil || string(input) != "stdin" {
			hostDone <- fmt.Errorf("stdin %q: %v", input, err)
			return
		}
		extended, err := io.ReadAll(b.Stderr())
		if err != nil || string(extended) != "client extended data" {
			hostDone <- fmt.Errorf("extended input %q: %v", extended, err)
			return
		}
		if _, err := b.Write(output); err != nil {
			hostDone <- err
			return
		}
		if _, err := b.Stderr().Write(stderr); err != nil {
			hostDone <- err
			return
		}
		if err := b.CloseWrite(); err != nil {
			hostDone <- err
			return
		}
		// EOF must not prematurely close the channel before the later status.
		<-statusAllowed
		if _, err := b.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{37})); err != nil {
			hostDone <- err
			return
		}
		hostDone <- b.Close()
	}()
	if _, err := io.WriteString(a, "stdin"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(a.Stderr(), "client extended data"); err != nil {
		t.Fatal(err)
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(a)
	if err != nil || !bytes.Equal(out, output) {
		t.Fatalf("stdout length %d, want %d: %v", len(out), len(output), err)
	}
	extended, err := io.ReadAll(a.Stderr())
	if err != nil || !bytes.Equal(extended, stderr) {
		t.Fatalf("stderr length %d, want %d: %v", len(extended), len(stderr), err)
	}
	allowStatus()
	req := forwardTestReceive(t, ar)
	if req.Type != "exit-status" || req.WantReply || !bytes.Equal(req.Payload, []byte{0, 0, 0, 37}) {
		t.Fatalf("status changed: %+v", req)
	}
	select {
	case _, ok := <-ar:
		if ok {
			t.Fatal("unexpected request after exit status")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("channel never closed after exit status")
	}
	if err := forwardTestReceive(t, hostDone); err != nil {
		t.Fatal(err)
	}
}

// gatedSSHOutput holds the session's managed output copy until the test allows
// consumption. Read the buffer only after Session.Wait joins that copy.
type gatedSSHOutput struct {
	buffer  bytes.Buffer
	release <-chan struct{}
}

func (w *gatedSSHOutput) Write(p []byte) (int, error) {
	<-w.release
	return w.buffer.Write(p)
}

// sshChannelWindow mirrors x/crypto's unexported channelWindowSize
// (64 * channelMaxPacket, channel.go:19-24 at v0.55.0). It is a calibration,
// not an invariant: nothing enforces that it still matches upstream. If
// x/crypto raises its window, flow-controlled-output silently stops being a
// flow-control case and merely duplicates buffered-client-output. Re-derive it
// when bumping x/crypto.
const sshChannelWindow = 64 * (1 << 15)

// Receiving exit-status is not the end of a Go session: Wait must also wait
// for channel closure and its managed stdout/stderr copies. These cases test
// those completion guarantees without assuming data/request wire order can be
// observed through the separate readers exposed by ssh.Channel.
func TestSSHForwardSessionWaitDrainsOutput(t *testing.T) {
	for _, tc := range []struct {
		name            string
		bytesPerStream  int
		eofBeforeStatus bool
	}{
		{"eof-before-status", 1024, true},
		{"buffered-client-output", 1024, false},
		// Three halves of one window across the two streams: more than one
		// hop's window, so forwarding blocks behind the guest's unread output,
		// but less than the two hops' windows combined, so the host's writes
		// still complete and it can send status while that block persists.
		{"flow-controlled-output", 3 * sshChannelWindow / 4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, _, _ := forwardTestProxy(t)
			sshClient := ssh.NewClient(client.conn, client.channels, client.requests)
			type sessionResult struct {
				session *ssh.Session
				err     error
			}
			opened := make(chan sessionResult, 1)
			go func() { session, err := sshClient.NewSession(); opened <- sessionResult{session, err} }()
			incoming := forwardTestReceive(t, server.channels)
			if incoming.ChannelType() != "session" {
				t.Fatalf("channel type %q, want session", incoming.ChannelType())
			}
			host, requests, err := incoming.Accept()
			if err != nil {
				t.Fatal(err)
			}
			result := forwardTestReceive(t, opened)
			if result.err != nil {
				t.Fatal(result.err)
			}
			session := result.session
			t.Cleanup(func() { _ = session.Close(); _ = host.Close() })
			release := make(chan struct{})
			allowOutput := sync.OnceFunc(func() { close(release) })
			t.Cleanup(allowOutput)
			stdout, stderr := &gatedSSHOutput{release: release}, &gatedSSHOutput{release: release}
			session.Stdout, session.Stderr = stdout, stderr
			if tc.eofBeforeStatus {
				allowOutput()
			}
			started := make(chan error, 1)
			go func() { started <- session.Start("test-output") }()
			request := forwardTestReceive(t, requests)
			if request.Type != "exec" || !request.WantReply {
				t.Fatalf("unexpected start request: %+v", request)
			}
			if err := request.Reply(true, nil); err != nil {
				t.Fatal(err)
			}
			go ssh.DiscardRequests(requests)
			if err := forwardTestReceive(t, started); err != nil {
				t.Fatal(err)
			}
			waited := make(chan error, 1)
			go func() { waited <- session.Wait() }()
			wantStdout := bytes.Repeat([]byte("o"), tc.bytesPerStream)
			wantStderr := bytes.Repeat([]byte("e"), tc.bytesPerStream)
			sent := make(chan error, 1)
			go func() {
				if _, err := host.Write(wantStdout); err != nil {
					sent <- err
					return
				}
				if _, err := host.Stderr().Write(wantStderr); err != nil {
					sent <- err
					return
				}
				if tc.eofBeforeStatus {
					if err := host.CloseWrite(); err != nil {
						sent <- err
						return
					}
				}
				if _, err := host.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{37})); err != nil {
					sent <- err
					return
				}
				// Session rejects unknown requests. Its reply proves it processed
				// the preceding exit-status while the channel is still open.
				ok, err := host.SendRequest("status-observed@upterm.test", true, nil)
				if err == nil && ok {
					err = errors.New("session accepted an unknown request")
				}
				sent <- err
			}()
			if err := forwardTestReceive(t, sent); err != nil {
				t.Fatal(err)
			}
			if !tc.eofBeforeStatus {
				if err := host.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-waited:
				t.Fatalf("Wait returned before channel closure or output consumption: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			allowOutput()
			if tc.eofBeforeStatus {
				if err := host.Close(); err != nil {
					t.Fatal(err)
				}
			}
			err = forwardTestReceive(t, waited)
			var exit *ssh.ExitError
			if !errors.As(err, &exit) || exit.ExitStatus() != 37 {
				t.Fatalf("Wait returned %v, want exit status 37", err)
			}
			if !bytes.Equal(stdout.buffer.Bytes(), wantStdout) || !bytes.Equal(stderr.buffer.Bytes(), wantStderr) {
				t.Fatalf("output truncated: stdout %d/%d bytes, stderr %d/%d bytes",
					stdout.buffer.Len(), len(wantStdout), stderr.buffer.Len(), len(wantStderr))
			}
		})
	}
}

func TestSSHForwardShutdownDrainsWorkers(t *testing.T) {
	for _, shutdown := range []string{"cancel", "downstream", "upstream"} {
		t.Run(shutdown, func(t *testing.T) {
			client, server, cancel, done := forwardTestProxy(t)
			a, _, _, _ := forwardTestChannel(t, client, server)
			type requestResult struct {
				ok  bool
				err error
			}
			requestDone := make(chan requestResult, 1)
			go func() { ok, err := a.SendRequest("unanswered", true, nil); requestDone <- requestResult{ok, err} }()
			globalDone := make(chan requestResult, 1)
			go func() {
				ok, _, err := server.conn.SendRequest("unanswered", true, nil)
				globalDone <- requestResult{ok, err}
			}()
			openDone := make(chan error, 1)
			go func() { _, _, err := client.conn.OpenChannel("unaccepted", nil); openDone <- err }()
			_ = forwardTestReceive(t, server.channels)
			switch shutdown {
			case "cancel":
				cancel()
			case "downstream":
				_ = client.conn.Close()
			case "upstream":
				_ = server.conn.Close()
			}
			select {
			case err := <-done:
				if shutdown == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel error: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("forwarder workers did not drain")
			}
			if result := forwardTestReceive(t, requestDone); result.ok {
				t.Fatalf("unanswered channel request returned: ok=%v err=%v", result.ok, result.err)
			}
			if result := forwardTestReceive(t, globalDone); result.ok {
				t.Fatalf("unanswered global request returned: ok=%v err=%v", result.ok, result.err)
			}
			if err := forwardTestReceive(t, openDone); err == nil {
				t.Fatal("unaccepted channel succeeded")
			}
		})
	}
}

func TestSSHRejectChannelsAfterHostRejectsKey(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig := &ssh.ClientConfig{User: "guest", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, downstream := forwardTestPair(t, &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), signer.PublicKey().Marshal()) {
			return nil, errors.New("unexpected guest key")
		}
		return nil, nil
	}}, clientConfig)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	hostDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			hostDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		config := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("guest key rejected by host")
		}}
		config.AddHostKey(signer)
		_, _, _, err = ssh.NewServerConn(conn, config)
		hostDone <- err
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _, _, upstreamErr := ssh.NewClientConn(conn, listener.Addr().String(), clientConfig)
	if upstreamErr == nil {
		t.Fatal("host accepted guest key")
	}
	if err := forwardTestReceive(t, hostDone); err == nil {
		t.Fatal("host authentication unexpectedly succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rejectSSHChannels(ctx, downstream, upstreamErr) }()
	for range 40 {
		ok, _, err := client.conn.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil || ok {
			t.Fatalf("failed-connection global request: %v %v", ok, err)
		}
	}
	_, _, err = client.conn.OpenChannel("session", nil)
	var rejection *ssh.OpenChannelError
	if !errors.As(err, &rejection) || rejection.Reason != ssh.ConnectionFailed || !strings.Contains(rejection.Message, "unable to authenticate") {
		t.Fatalf("unreadable upstream failure: %v", err)
	}
	_ = forwardTestReceive(t, done)
}

func TestSSHRejectChannelsBoundedWait(t *testing.T) {
	client, downstream := forwardTestPair(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rejectSSHChannels(ctx, downstream, errors.New("upstream unavailable")) }()
	if err := forwardTestReceive(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error: %v", err)
	}
	if err := client.conn.Wait(); err == nil {
		t.Fatal("connection remained open after timeout")
	}
}

func TestSSHForwardOriginClosePreservesConnection(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	a, _, b, br := forwardTestChannel(t, client, server)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-br:
		if ok {
			t.Fatal("unexpected request")
		}
	case <-time.After(time.Second):
		t.Fatal("origin close did not close destination channel")
	}
	_, err := b.Write([]byte("closed"))
	if err == nil {
		t.Fatal("destination channel still writable")
	}
	a2, ar2, b2, br2 := forwardTestChannel(t, client, server)
	go ssh.DiscardRequests(ar2)
	go ssh.DiscardRequests(br2)
	_ = a2.Close()
	_ = b2.Close()
}

// Pending replies plus ingress beyond x/crypto's 16-entry queues used to pin
// both muxes, so even closing the transports could not release the forwarder.
func TestSSHForwardCancelWithQueuedRequests(t *testing.T) {
	for _, kind := range []string{"global", "channel"} {
		t.Run(kind, func(t *testing.T) {
			client, server, cancel, done := forwardTestProxy(t)
			senders := []sshRequestSender{client.conn, server.conn}
			requests := []<-chan *ssh.Request{server.requests, client.requests}
			if kind == "channel" {
				a, ar, b, br := forwardTestChannel(t, client, server)
				senders = []sshRequestSender{sshChannelRequestSender{a}, sshChannelRequestSender{b}}
				requests = []<-chan *ssh.Request{br, ar}
			}
			pendingDone := make(chan bool, 2)
			for i, sender := range senders {
				go func() { ok, _, _ := sender.SendRequest("unanswered", true, nil); pendingDone <- ok }()
				_ = forwardTestReceive(t, requests[i])
			}
			for range 40 {
				for _, sender := range senders {
					if _, _, err := sender.SendRequest("queued", false, nil); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Give both relay muxes time to consume the transmitted packets before
			// cancellation; this is the scheduling window of the original deadlock.
			time.Sleep(50 * time.Millisecond)
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not drain full request queues")
			}
			for range 2 {
				if forwardTestReceive(t, pendingDone) {
					t.Fatal("unanswered request succeeded")
				}
			}
		})
	}
}

func TestSSHForwardOriginCloseWithPendingReply(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	a, _, _, br := forwardTestChannel(t, client, server)
	pendingDone := make(chan bool, 1)
	go func() { ok, _ := a.SendRequest("unanswered", true, nil); pendingDone <- ok }()
	pending := forwardTestReceive(t, br)
	// Releasing the reply only in cleanup also lets the old implementation exit
	// after the assertion fails; a successful run cannot depend on this reply.
	defer func() { _ = pending.Reply(false, nil) }()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-br:
		if ok {
			t.Fatal("unexpected request")
		}
	case <-time.After(time.Second):
		t.Fatal("origin CLOSE blocked by unanswered request")
	}
	if forwardTestReceive(t, pendingDone) {
		t.Fatal("aborted request succeeded")
	}
	a2, ar2, b2, br2 := forwardTestChannel(t, client, server)
	go ssh.DiscardRequests(ar2)
	go ssh.DiscardRequests(br2)
	_ = a2.Close()
	_ = b2.Close()
}

// stalledSSHConn models a peer that has stopped reading: writes toward it block
// until the transport is closed, which is the only thing that releases them.
type stalledSSHConn struct {
	ssh.Conn
	closed    chan struct{}
	channels  chan ssh.NewChannel
	closeOnce sync.Once
}

func (c *stalledSSHConn) Close() error {
	// A real mux stops delivering opens once its transport is gone.
	c.closeOnce.Do(func() { close(c.closed); close(c.channels) })
	return nil
}

func (c *stalledSSHConn) Wait() error {
	<-c.closed
	return io.EOF
}

// stalledNewChannel blocks in Reject the way a real one blocks writing to a
// transport whose peer is not draining it. A nil release rejects at once.
type stalledNewChannel struct {
	ssh.NewChannel
	release <-chan struct{}
}

func (c stalledNewChannel) Reject(ssh.RejectionReason, string) error {
	if c.release != nil {
		<-c.release
		return net.ErrClosed
	}
	return nil
}

// Rejecting the opens the mux already buffered happens before the transport is
// closed, so those are writes. The deadline has to stay enforced across them,
// or a peer that stopped reading pins the connection and its workers forever.
func TestSSHRejectChannelsBoundedThroughBufferedWrites(t *testing.T) {
	conn := &stalledSSHConn{closed: make(chan struct{}), channels: make(chan ssh.NewChannel, 2)}
	// The first open is answered by the select inside rejectSSHChannels and
	// returns at once, so the deferred rejection below runs with the deadline
	// still live. The second is what the mux had buffered, and it stalls.
	conn.channels <- stalledNewChannel{}
	conn.channels <- stalledNewChannel{release: conn.closed}
	requests := make(chan *ssh.Request)
	close(requests)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- rejectSSHChannels(ctx, sshPeer{conn, conn.channels, requests}, errors.New("upstream unavailable"))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rejection outlived its deadline; a stalled peer pins the connection")
	}
}

// The concurrent-open cap must bound opens in progress, not established
// channels: every guest on a session holds a channel open on the host
// connection for as long as it is joined.
func TestSSHForwardEstablishedChannelsAreNotCapped(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	opened := make([]ssh.Channel, 0, maxSSHConcurrentChannelOpens+1)
	for i := range maxSSHConcurrentChannelOpens + 1 {
		a, ar, b, br := forwardTestChannel(t, client, server)
		if a == nil || b == nil {
			t.Fatalf("channel %d rejected while %d were open", i, len(opened))
		}
		go ssh.DiscardRequests(ar)
		go ssh.DiscardRequests(br)
		opened = append(opened, a, b)
	}
	for _, ch := range opened {
		_ = ch.Close()
	}
}

// recordingRequestSender stands in for a destination so a test can hold one
// send open and observe exactly what want_reply each request carried.
type recordingRequestSender struct {
	entered chan struct{}
	release chan struct{}
	mu      sync.Mutex
	names   []string
	awaited map[string]bool
}

func (s *recordingRequestSender) SendRequest(name string, wantReply bool, _ []byte) (bool, []byte, error) {
	s.mu.Lock()
	s.names = append(s.names, name)
	if s.awaited == nil {
		s.awaited = map[string]bool{}
	}
	s.awaited[name] = wantReply
	first := len(s.names) == 1
	s.mu.Unlock()
	if first {
		close(s.entered)
		<-s.release
	}
	return true, nil, nil
}

// Once the source is gone its reply cannot be delivered, so the tail behind it
// goes out without want_reply. That is what removes the need to force the
// sender free, and with it the CLOSE that used to race the request write.
func TestSSHForwardTailAfterSourceCloseKeepsRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		defer cancel(nil)
		sender := &recordingRequestSender{entered: make(chan struct{}), release: make(chan struct{})}
		incoming := make(chan *ssh.Request)
		aborts := make(chan struct{}, 1)

		done := make(chan struct{})
		go func() {
			defer close(done)
			sshForwarder{ctx: ctx, cancel: cancel}.requests(
				sender, incoming, nil, func() { aborts <- struct{}{} }, sshRequestAbortGrace, nil)
		}()

		// Occupy the serial sender, so everything after this is queued rather
		// than dispatched while the source is still connected.
		incoming <- &ssh.Request{Type: "blocking"}
		<-sender.entered
		incoming <- &ssh.Request{Type: "tail"}
		incoming <- &ssh.Request{Type: "unanswerable", WantReply: true}
		close(incoming)
		synctest.Wait() // the forwarder has observed the closed ingress
		close(sender.release)
		<-done

		if got := sender.names; !slices.Equal(got, []string{"blocking", "tail", "unanswerable"}) {
			t.Fatalf("requests reaching the destination: %q", got)
		}
		if sender.awaited["unanswerable"] {
			t.Fatal("waited for a reply the departed source could not receive")
		}
		select {
		case <-aborts:
			t.Fatal("forced the sender free when no reply was awaited")
		default:
		}
	})
}

func TestSSHForwardRequestQueueOverflow(t *testing.T) {
	for _, size := range []string{"count", "bytes"} {
		t.Run(size, func(t *testing.T) {
			client, server, _, done := forwardTestProxy(t)
			pendingDone := make(chan bool, 1)
			go func() { ok, _, _ := client.conn.SendRequest("unanswered", true, nil); pendingDone <- ok }()
			_ = forwardTestReceive(t, server.requests)
			payload := []byte(nil)
			count := 300
			if size == "bytes" {
				payload = make([]byte, 64*1024)
				count = 20
			}
			for range count {
				if _, _, err := client.conn.SendRequest("queued", false, payload); err != nil {
					break
				}
			}
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "request queue") {
					t.Fatalf("queue overflow error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("unbounded queue kept connection alive")
			}
			if forwardTestReceive(t, pendingDone) {
				t.Fatal("unanswered request succeeded")
			}
		})
	}
}

func TestSSHForwardQueuedTailBeforeClose(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	_, ar, b, br := forwardTestChannel(t, client, server)
	go ssh.DiscardRequests(br)
	sent := make(chan error, 1)
	go func() {
		for i := range 40 {
			if _, err := b.SendRequest("tail", false, []byte{byte(i)}); err != nil {
				sent <- err
				return
			}
		}
		if _, err := b.SendRequest("exit-status", false, []byte{0, 0, 0, 37}); err != nil {
			sent <- err
			return
		}
		sent <- b.Close()
	}()
	for i := range 40 {
		req := forwardTestReceive(t, ar)
		if req.Type != "tail" || req.WantReply || !bytes.Equal(req.Payload, []byte{byte(i)}) {
			t.Fatalf("queued tail %d changed: %+v", i, req)
		}
	}
	req := forwardTestReceive(t, ar)
	if req.Type != "exit-status" || !bytes.Equal(req.Payload, []byte{0, 0, 0, 37}) {
		t.Fatalf("exit status changed: %+v", req)
	}
	select {
	case _, ok := <-ar:
		if ok {
			t.Fatal("request after exit status")
		}
	case <-time.After(time.Second):
		t.Fatal("channel did not close")
	}
	if err := forwardTestReceive(t, sent); err != nil {
		t.Fatal(err)
	}
}

// A request which has already replied successfully must not be mistaken for
// an unanswered request when its sender immediately sends status and CLOSE.
func TestSSHForwardReplyThenStatusAndClose(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	for range 16 {
		a, _, _, br := forwardTestChannel(t, client, server)
		sent := make(chan error, 1)
		go func() {
			ok, err := a.SendRequest("before-status", true, nil)
			if err != nil || !ok {
				sent <- fmt.Errorf("request reply: %v %v", ok, err)
				return
			}
			if _, err := a.SendRequest("exit-status", false, []byte{0, 0, 0, 37}); err != nil {
				sent <- err
				return
			}
			sent <- a.Close()
		}()
		request := forwardTestReceive(t, br)
		if err := request.Reply(true, nil); err != nil {
			t.Fatal(err)
		}
		status := forwardTestReceive(t, br)
		if status.Type != "exit-status" || !bytes.Equal(status.Payload, []byte{0, 0, 0, 37}) {
			t.Fatalf("status changed: %+v", status)
		}
		select {
		case _, ok := <-br:
			if ok {
				t.Fatal("request after exit status")
			}
		case <-time.After(time.Second):
			t.Fatal("channel did not close")
		}
		if err := forwardTestReceive(t, sent); err != nil {
			t.Fatal(err)
		}
	}
}

// The producer completes CHANNEL_CLOSE (including its acknowledgement) before
// closing its transport. All bytes were accepted by SSH before that disconnect.
func forwardTestBufferedTransportClose(t *testing.T, receiver, producer sshPeer, stdout, stderr []byte) (ssh.Channel, <-chan *ssh.Request, <-chan error) {
	t.Helper()
	a, ar, b, br := forwardTestChannel(t, receiver, producer)
	sent := make(chan error, 1)
	go func() {
		if _, err := b.Write(stdout); err != nil {
			sent <- err
			return
		}
		if _, err := b.Stderr().Write(stderr); err != nil {
			sent <- err
			return
		}
		if _, err := b.SendRequest("exit-status", false, []byte{0, 0, 0, 37}); err != nil {
			sent <- err
			return
		}
		if err := b.Close(); err != nil {
			sent <- err
			return
		}
		for request := range br {
			_ = request.Reply(false, nil)
		}
		sent <- producer.conn.Close()
	}()
	return a, ar, sent
}

func TestSSHForwardTransportCloseDrainsBufferedData(t *testing.T) {
	for _, direction := range []string{"upstream", "downstream"} {
		for _, stream := range []string{"stdout", "stderr", "mixed", "pending-global"} {
			t.Run(direction+"/"+stream, func(t *testing.T) {
				client, server, _, done := forwardTestProxy(t)
				receiver, producer := client, server
				if direction == "downstream" {
					receiver, producer = server, client
				}
				var stdout, stderr []byte
				switch stream {
				case "stdout":
					stdout = bytes.Repeat([]byte("o"), 3*1024*1024)
				case "stderr":
					stderr = bytes.Repeat([]byte("e"), 3*1024*1024)
				default:
					stdout = bytes.Repeat([]byte("o"), 1536*1024)
					stderr = bytes.Repeat([]byte("e"), 1536*1024)
				}
				var globalDone chan bool
				if stream == "pending-global" {
					globalDone = make(chan bool, 1)
					go func() { ok, _, _ := producer.conn.SendRequest("pending-at-disconnect", true, nil); globalDone <- ok }()
					_ = forwardTestReceive(t, receiver.requests)
				}
				a, ar, sent := forwardTestBufferedTransportClose(t, receiver, producer, stdout, stderr)
				if err := forwardTestReceive(t, sent); err != nil {
					t.Fatal(err)
				}
				// The downstream window holds only 2 MiB. With no reads yet, a completed
				// forwarder here necessarily abandoned some of the 3 MiB already received.
				select {
				case err := <-done:
					t.Fatalf("forwarder stopped before buffered output drained: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				type readResult struct {
					data []byte
					err  error
				}
				extended := make(chan readResult, 1)
				go func() { data, err := io.ReadAll(a.Stderr()); extended <- readResult{data, err} }()
				got, err := io.ReadAll(a)
				if err != nil || !bytes.Equal(got, stdout) {
					t.Fatalf("stdout: got %d, want %d: %v", len(got), len(stdout), err)
				}
				ext := forwardTestReceive(t, extended)
				if ext.err != nil || !bytes.Equal(ext.data, stderr) {
					t.Fatalf("stderr: got %d, want %d: %v", len(ext.data), len(stderr), ext.err)
				}
				status := forwardTestReceive(t, ar)
				if status.Type != "exit-status" || status.WantReply || !bytes.Equal(status.Payload, []byte{0, 0, 0, 37}) {
					t.Fatalf("status changed: %+v", status)
				}
				select {
				case _, ok := <-ar:
					if ok {
						t.Fatal("request after status")
					}
				case <-time.After(time.Second):
					t.Fatal("channel did not close")
				}
				_ = forwardTestReceive(t, done)
				if globalDone != nil && forwardTestReceive(t, globalDone) {
					t.Fatal("unanswered global request succeeded")
				}
			})
		}
	}
}

func TestSSHForwardTransportDrainBounded(t *testing.T) {
	for _, shutdown := range []string{"timeout", "cancel"} {
		t.Run(shutdown, func(t *testing.T) {
			client, server, cancel, done := forwardTestProxy(t)
			_, _, sent := forwardTestBufferedTransportClose(t, client, server, bytes.Repeat([]byte("x"), 3*1024*1024), nil)
			if err := forwardTestReceive(t, sent); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				t.Fatalf("no buffer drain grace: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if shutdown == "cancel" {
				cancel()
			}
			limit := 7 * time.Second
			if shutdown == "cancel" {
				limit = time.Second
			}
			select {
			case err := <-done:
				if shutdown == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel during drain: %v", err)
				}
				if shutdown == "timeout" && (err == nil || !strings.Contains(err.Error(), "drain timed out")) {
					t.Fatalf("stalled drain: %v", err)
				}
			case <-time.After(limit):
				t.Fatal("stalled reader prevented bounded shutdown")
			}
		})
	}
}

// Pause after the real peer has replied, before the forwarder can relay that
// reply. This exposes a CLOSE overtaking an already-successful request without
// depending on which SSH worker the scheduler happens to run first.
type forwardTestReplyGateConn struct {
	ssh.Conn
	received chan struct{}
	release  <-chan struct{}
}

func (c forwardTestReplyGateConn) OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	channel, requests, err := c.Conn.OpenChannel(name, payload)
	if err != nil {
		return nil, nil, err
	}
	return forwardTestReplyGateChannel{Channel: channel, received: c.received, release: c.release}, requests, nil
}

type forwardTestReplyGateChannel struct {
	ssh.Channel
	received chan struct{}
	release  <-chan struct{}
}

func (c forwardTestReplyGateChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	ok, err := c.Channel.SendRequest(name, wantReply, payload)
	if name == "shell" && wantReply {
		close(c.received)
		<-c.release
	}
	return ok, err
}

func TestSSHForwardSuccessReplyBeforePeerClose(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprint(reverse), func(t *testing.T) {
			client, downstream := forwardTestPair(t, nil, nil)
			upstream, server := forwardTestPair(t, nil, nil)
			received, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			origin, destination := client, server
			if reverse {
				downstream.conn = forwardTestReplyGateConn{downstream.conn, received, release}
				origin, destination = server, client
			} else {
				upstream.conn = forwardTestReplyGateConn{upstream.conn, received, release}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- forwardSSH(ctx, downstream, upstream, abortConnection, discardLogger()) }()
			t.Cleanup(func() { cancel(); _ = forwardTestReceive(t, done) })
			a, ar, b, br := forwardTestChannel(t, origin, destination)
			type response struct {
				ok  bool
				err error
			}
			replied := make(chan response, 1)
			go func() { ok, err := a.SendRequest("shell", true, nil); replied <- response{ok, err} }()
			request := forwardTestReceive(t, br)
			if err := request.Reply(true, nil); err != nil {
				t.Fatal(err)
			}
			select {
			case <-received: // The forwarder already holds the peer's success.
			case <-time.After(3 * time.Second):
				t.Fatal("forwarder did not receive the success reply")
			}
			output := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(a); output <- data }()
			if _, err := b.Write([]byte("PTY is required.\n")); err != nil {
				t.Fatal(err)
			}
			if _, err := b.SendRequest("exit-status", false, []byte{0, 0, 0, 1}); err != nil {
				t.Fatal(err)
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			status := forwardTestReceive(t, ar)
			if status.Type != "exit-status" || !bytes.Equal(status.Payload, []byte{0, 0, 0, 1}) {
				t.Fatalf("changed exit status: %+v", status)
			}
			if data := forwardTestReceive(t, output); string(data) != "PTY is required.\n" {
				t.Fatalf("lost output: %q", data)
			}
			select {
			case result := <-replied:
				t.Fatalf("channel closed before the success reply could be forwarded: ok=%v err=%v", result.ok, result.err)
			case <-time.After(100 * time.Millisecond):
			}
			unblock()
			if result := forwardTestReceive(t, replied); result.err != nil || !result.ok {
				t.Fatalf("lost success reply: ok=%v err=%v", result.ok, result.err)
			}
			select {
			case _, ok := <-ar:
				if ok {
					t.Fatal("unexpected request after exit status")
				}
			case <-time.After(time.Second):
				t.Fatal("channel did not close after its reply was delivered")
			}
		})
	}
}

func TestSSHForwardSimultaneousCloseWithPendingReplies(t *testing.T) {
	client, server, _, _ := forwardTestProxy(t)
	a, ar, b, br := forwardTestChannel(t, client, server)
	type response struct {
		ok  bool
		err error
	}
	replies := make(chan response, 2)
	go func() { ok, err := a.SendRequest("pending-a", true, nil); replies <- response{ok, err} }()
	go func() { ok, err := b.SendRequest("pending-b", true, nil); replies <- response{ok, err} }()
	pendingA := forwardTestReceive(t, br)
	pendingB := forwardTestReceive(t, ar)
	defer func() { _ = pendingA.Reply(false, nil); _ = pendingB.Reply(false, nil) }()
	closed := make(chan error, 2)
	go func() { closed <- a.Close() }()
	go func() { closed <- b.Close() }()
	for range 2 {
		if err := forwardTestReceive(t, closed); err != nil {
			t.Fatal(err)
		}
		if result := forwardTestReceive(t, replies); result.err == nil && result.ok {
			t.Fatal("unanswered request succeeded after both peers closed")
		}
	}
	// Only the channel was closed; aborting its pending replies must leave
	// the transport available for another channel in either direction.
	for _, direction := range [][2]sshPeer{{client, server}, {server, client}} {
		a, _, b, _ := forwardTestChannel(t, direction[0], direction[1])
		_ = a.Close()
		_ = b.Close()
	}
}

// TestSSHForwardAbortCutsBufferedData pins the documented exception to the
// forwarder's data-before-CLOSE guarantee.
//
// channelDirection normally closes the destination only after both the request
// tail and the data copy have drained, so a peer reading until CHANNEL_CLOSE
// sees every forwarded byte. The abort path skips that: abortPending closes the
// destination from inside requests, before streams.Wait(), to release a sender
// whose source has gone away. Anything still queued behind a blocked Write is
// lost, and copySSHChannel discards the resulting error.
//
// The other abort cases here (TestSSHForwardOriginCloseWithPendingReply,
// TestSSHForwardSimultaneousCloseWithPendingReplies) have no data in flight, so
// they never exercise that loss. This one stalls the destination so the copy is
// blocked when the abort lands, and pins the truncation rather than leaving the
// godoc's exception untested.
//
// The figures are stable because the pipeline saturates: the origin gets
// exactly two windows accepted, the destination ends up holding exactly one,
// and the missing window is the cut. Every assertion here is an upper bound, so
// the gate that waits for two windows to be accepted is what keeps the case
// from passing on a run where nothing moved — measured, not assumed.
//
// Every wait here is sized against forwardTestPair's absolute 10s transport
// deadline: 3s to fill the pipeline, 1s of control, 3s for the abort to land.
// Past that deadline the transports are gone and no bound can be informative,
// so the waits stay inside it rather than outlasting it.
func TestSSHForwardAbortCutsBufferedData(t *testing.T) {
	// A stalled destination absorbs about two windows before anything blocks:
	// one in b's own buffer, and one more in the forwarder's source-side buffer
	// because reading from a replenishes a's credit. Two windows therefore sits
	// exactly at capacity and the copy finishes given a moment — measured, not
	// assumed. Four leaves the origin unable to finish, which is what makes
	// "the copy was blocked when the abort landed" true rather than incidental.
	const sent = 4 * sshChannelWindow

	client, server, _, _ := forwardTestProxy(t)
	a, ar, b, br := forwardTestChannel(t, client, server)
	go ssh.DiscardRequests(ar)

	// b never reads, so the forwarder's copy blocks once b's window fills and
	// a's own window stops being replenished. Neither write can complete.
	// Writing in chunks publishes progress, which the gate below needs.
	var accepted atomic.Int64
	written := make(chan int, 1)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		chunk := bytes.Repeat([]byte("x"), 64<<10)
		total := 0
		for total < sent {
			n, err := a.Write(chunk)
			total += n
			accepted.Add(int64(n))
			if err != nil {
				break
			}
		}
		written <- total
	}()

	// An unanswered request with a source that then disappears is what arms the
	// abort. b receives it and deliberately never replies until cleanup.
	pendingDone := make(chan bool, 1)
	go func() { ok, _ := a.SendRequest("unanswered", true, nil); pendingDone <- ok }()
	pending := forwardTestReceive(t, br)
	defer func() { _ = pending.Reply(false, nil) }()

	// Lower bound, and the load-bearing one. Every assertion below is an upper
	// bound, so without this the case passes when nothing ever moved: a.Close()
	// makes Write return 0, ReadAll returns 0, and 0 is under every ceiling.
	// Passing a full window means the forwarder has drained a window out of a
	// and pushed it at b, so there is real data in the pipeline to cut.
	//
	// Half a window past that, rather than a second whole one. Two windows is
	// the pipeline's theoretical maximum, and waiting for the maximum makes the
	// gate a throughput test: under load it lands one 64 KiB chunk short and
	// fails a case that had in fact filled the pipeline. Measured on macOS at
	// 3 of 40 runs before the change this test arrived in, and 1 of 40 after,
	// so it is the gate rather than anything it guards. The margin above one
	// window is what proves the forwarder is pushing, and half a window is an
	// unambiguous margin.
	//
	// The budget is not ours to choose freely: forwardTestPair puts an absolute
	// 10s deadline on both transports, so a wait longer than that cannot make
	// progress, it can only turn a dead transport into a late and misleading
	// "nothing to cut". Stay well inside it, and watch the writer as well as the
	// clock — if it stops early the transport or channel ended, which is a
	// different failure and deserves to say so.
	const loaded = sshChannelWindow + sshChannelWindow/2
	gate := time.After(3 * time.Second)
	for accepted.Load() < loaded {
		select {
		case <-writerDone:
			t.Fatalf("origin stopped writing at %d of the %d bytes the pipeline needs; "+
				"the channel or transport ended before the abort was armed", accepted.Load(), loaded)
		case <-gate:
			t.Fatalf("only %d of the %d bytes needed entered the forwarding path within the transport budget",
				accepted.Load(), loaded)
		case <-time.After(time.Millisecond):
		}
	}

	// Control: with the source still open, nothing closes the destination, and
	// this outlasts sshRequestAbortGrace. Without it, the close below could be
	// any incidental close rather than the abort.
	select {
	case _, ok := <-br:
		if !ok {
			t.Fatal("destination closed while the source was still open")
		}
		t.Fatal("unexpected second request")
	case <-time.After(10 * sshRequestAbortGrace):
	}

	// What the origin had successfully written by the time the abort was armed.
	// The destination must end up with strictly less than this.
	inFlight := accepted.Load()

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// b's request channel closing is the abort landing: the forwarder closed
	// the destination without waiting for the blocked copy.
	select {
	case _, ok := <-br:
		if ok {
			t.Fatal("unexpected request after source close")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("abort did not close the destination while its data copy was blocked")
	}

	if forwardTestReceive(t, pendingDone) {
		t.Fatal("aborted request succeeded")
	}

	// Whatever reached b's buffer before the abort is still readable; the rest
	// is gone. Comparing against what the origin actually wrote — not against
	// `sent` — is what makes this a statement about cut data rather than about
	// an unfinished write.
	got, err := io.ReadAll(b)
	if err != nil {
		t.Fatalf("draining destination after abort: %v", err)
	}
	if int64(len(got)) >= inFlight {
		t.Fatalf("destination received %d bytes of the %d the origin wrote; expected the abort to cut the copy",
			len(got), inFlight)
	}
	if n := forwardTestReceive(t, written); n >= sent {
		t.Fatalf("origin wrote all %d bytes; the copy was never actually blocked", sent)
	}
}

// The stalled-direction watchdog has to arm on source closure itself, not on
// the teardown reaching a particular line: the serial sender can still be
// blocked in SendRequest, and the deferred wait for it means requests would not
// return.
func TestRequestsReportsSourceClosureWhileTheSenderIsBlocked(t *testing.T) {
	incoming := make(chan *ssh.Request)
	blocked := make(chan struct{})
	defer close(blocked)

	entered := make(chan struct{})
	var enterOnce sync.Once
	sender := senderFunc(func(string, bool, []byte) (bool, []byte, error) {
		enterOnce.Do(func() { close(entered) })
		<-blocked
		return false, nil, nil
	})

	closed := make(chan struct{})
	f := sshForwarder{ctx: t.Context(), cancel: func(error) {}}
	go f.requests(sender, incoming, sync.OnceFunc(func() { close(closed) }), nil, 0, nil)

	incoming <- &ssh.Request{Type: "window-change"}
	<-entered // the sender has dispatched the request and is blocked in SendRequest
	close(incoming)

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("source closure was not reported while the sender was blocked")
	}
}

// senderFunc adapts a function to sshRequestSender.
type senderFunc func(string, bool, []byte) (bool, []byte, error)

func (s senderFunc) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return s(name, wantReply, payload)
}

// channelGate blocks whichever of a channel's methods the test chooses, the way
// x/crypto's channel blocks when the window is exhausted (Write) or the socket
// is full (any of them, since each is a transport write under the channel's
// write mutex). A nil gate channel means that method is not blocked.
type channelGate struct {
	write   chan struct{}
	request chan struct{}
	close   chan struct{}

	closed    chan struct{}
	closeOnce sync.Once
}

func newChannelGate() *channelGate {
	return &channelGate{closed: make(chan struct{})}
}

// closeCalled reports whether the gated channel has been closed. With Write
// gated, channelDirection never reaches its own Close, so this is only ever
// true because the watchdog acted.
func (g *channelGate) closeCalled() bool {
	select {
	case <-g.closed:
		return true
	default:
		return false
	}
}

// releaseAll unblocks every gated method, so a test can require that the code
// under test actually unwinds rather than merely that it fired a callback.
func (g *channelGate) releaseAll() {
	for _, c := range []chan struct{}{g.write, g.request, g.close} {
		if c != nil {
			close(c)
		}
	}
}

type gatedChannel struct {
	ssh.Channel
	gate *channelGate
}

func (g gatedChannel) Write(p []byte) (int, error) {
	if g.gate.write != nil {
		<-g.gate.write
	}
	return g.Channel.Write(p)
}

func (g gatedChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	if g.gate.request != nil {
		<-g.gate.request
	}
	return g.Channel.SendRequest(name, wantReply, payload)
}

func (g gatedChannel) Close() error {
	if g.gate.close != nil {
		<-g.gate.close
	}
	g.gate.closeOnce.Do(func() { close(g.gate.closed) })
	return g.Channel.Close()
}

// openTestChannel opens a "session" channel on a peer's connection and discards
// the requests that come back on it. Something on the far side has to be
// accepting concurrently: OpenChannel blocks until the peer answers.
func openTestChannel(t *testing.T, peer sshPeer) ssh.Channel {
	t.Helper()
	channel, requests, err := peer.conn.OpenChannel("session", nil)
	require.NoError(t, err)
	go ssh.DiscardRequests(requests)
	t.Cleanup(func() { _ = channel.Close() })
	return channel
}

// acceptTestChannel accepts the next channel offered to a peer and discards its
// requests, reporting nil once the peer stops offering any. It reports rather
// than fails because its callers run it on goroutines of their own, where the
// testing package forbids FailNow.
func acceptTestChannel(peer sshPeer) ssh.Channel {
	incoming, ok := <-peer.channels
	if !ok {
		return nil
	}
	channel, requests, err := incoming.Accept()
	if err != nil {
		return nil
	}
	go ssh.DiscardRequests(requests)
	return channel
}

// forwardTestDirection builds one direction the way the forwarder really sees
// it: a source on one connection and a destination on another, never two ends
// of the same channel.
//
// Three things here are not optional. OpenChannel blocks until the peer
// accepts, so the accept has to run concurrently or the fixture deadlocks
// against itself. Source and destination must be independent connections, or
// the copy feeds forwarded bytes straight back into the source. And the source
// end is closed by its own peer, because the returned request channel is a
// plain Go channel — closing it signals source closure to channelDirection but
// produces no EOF on a real stream.
func forwardTestDirection(t *testing.T, gate *channelGate) (destination, source *sshForwardChannel, requests chan *ssh.Request, closeSource func()) {
	t.Helper()

	open := func(peerA, peerB sshPeer) (near, far ssh.Channel) {
		t.Helper()
		accepted := make(chan ssh.Channel, 1)
		go func() { accepted <- acceptTestChannel(peerB) }()
		near = openTestChannel(t, peerA)
		far = <-accepted
		require.NotNil(t, far, "the peer failed to accept the channel")
		return near, far
	}

	// The producer connection: its far end is what channelDirection reads.
	producerNear, producerFar := open(forwardTestPair(t, nil, nil))
	// The consumer connection: its far end is what channelDirection writes to,
	// gated so the test can stall it.
	consumerNear, _ := open(forwardTestPair(t, nil, nil))

	// Give the source something to forward, so the copy is inside the
	// destination's Write by the time the source closes.
	_, err := producerNear.Write([]byte("shell output"))
	require.NoError(t, err)

	return &sshForwardChannel{Channel: gatedChannel{Channel: consumerNear, gate: gate}},
		&sshForwardChannel{Channel: producerFar},
		make(chan *ssh.Request),
		func() { _ = producerNear.Close() }
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// newTestForwarder builds a forwarder whose cancel is observable and whose
// timers are short enough to run in a test.
func newTestForwarder(t *testing.T, scope sshAbortScope, cancelled chan<- error) sshForwarder {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	return sshForwarder{
		ctx:          ctx,
		scope:        scope,
		drainTimeout: 100 * time.Millisecond,
		abortGrace:   50 * time.Millisecond,
		cancel: func(err error) {
			cancel(err)
			select {
			case cancelled <- err:
			default:
			}
		},
	}
}

func TestChannelDirectionAbortsAStalledDestination(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(*channelGate)
	}{
		// The plain case: the guest stopped reading, so the window is
		// exhausted and the copy is stuck in Write.
		{"write blocked", func(g *channelGate) { g.write = make(chan struct{}) }},
		// Close blocked too, which is what a full socket looks like: Close is a
		// transport write under the same mutex the blocked Write holds. A
		// sequential abort could never reach its own timer here.
		{"write and close blocked", func(g *channelGate) {
			g.write = make(chan struct{})
			g.close = make(chan struct{})
		}},
		// SendRequest blocked, so the request pump cannot return. The watchdog
		// arms on observed source closure, not on that return.
		{"write and requests blocked", func(g *channelGate) {
			g.write = make(chan struct{})
			g.request = make(chan struct{})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cancelled := make(chan error, 1)
			f := newTestForwarder(t, abortConnection, cancelled)

			gate := newChannelGate()
			tt.setup(gate)
			destination, source, requests, closeSource := forwardTestDirection(t, gate)

			returned := make(chan struct{})
			go func() {
				defer close(returned)
				f.channelDirection(destination, source, requests)
			}()

			if gate.request != nil {
				// Gating SendRequest proves nothing unless a request is
				// actually in flight through the serial sender.
				requests <- &ssh.Request{Type: "window-change"}
			}
			closeSource()
			close(requests) // source CLOSE, with no reply pending

			select {
			case err := <-cancelled:
				require.ErrorIs(t, err, errSSHChannelDrainStalled)
			case <-time.After(10 * time.Second):
				t.Fatal("a stalled direction was never aborted")
			}

			// Cancelling proves the watchdog fired; it does not prove the
			// direction unwinds. Release the gates and require that it does,
			// or the goroutines this change exists to free are still stuck.
			gate.releaseAll()
			select {
			case <-returned:
			case <-time.After(10 * time.Second):
				t.Fatal("channelDirection never returned after the abort")
			}
		})
	}
}

// Once the connection is draining, forwardSSH owns the bound on a stalled
// channel and the watchdog must keep its hands off.
//
// Both bounds arm within moments of each other on a shutdown, and before this
// they ran on identical timeouts — sshForwardChannelDrainTimeout equalled
// sshForwardDrainTimeout — so which one resolved the stall came down to
// scheduling. Closing the channel first completes the drain loop and suppresses
// the "drain timed out" error TestSSHForwardTransportDrainBounded requires,
// which is how this surfaced: as an error-message flake on Windows CI, on a
// test that had nothing to do with this change.
//
// Nothing is lost by standing down. forwardSSH closes both transports when its
// own timer expires, which releases a blocked write more thoroughly than
// closing one channel does.
func TestChannelDirectionYieldsAStalledChannelToTheTransportDrain(t *testing.T) {
	cancelled := make(chan error, 1)
	f := newTestForwarder(t, abortConnection, cancelled)

	// Already draining when the direction starts, so the watchdog has to decline
	// at its first decision point rather than mid-wait.
	draining := make(chan struct{})
	close(draining)
	f.draining = draining

	gate := newChannelGate()
	gate.write = make(chan struct{})
	destination, source, requests, closeSource := forwardTestDirection(t, gate)

	go f.channelDirection(destination, source, requests)
	closeSource()
	close(requests)

	// Well past f.drainTimeout plus f.abortGrace, which together are 150ms here.
	select {
	case err := <-cancelled:
		t.Fatalf("the watchdog aborted a draining connection: %v", err)
	case <-time.After(time.Second):
	}
	require.False(t, gate.closeCalled(),
		"the watchdog closed a channel a draining connection was already bounding")

	gate.releaseAll()
}

// syncBuffer collects log output written from the watchdog's goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	return len(p), nil
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.buf)
}

// Both escalation steps have to say so. From the daemon's side a dropped guest
// is otherwise indistinguishable from one that hung up: the host logs why it
// stopped feeding a guest, but nothing here recorded that the forwarder then
// closed the channel, or that it took the whole connection down behind it.
//
// Waited for rather than read once, because each line is emitted from its own
// goroutine — the abort must not be able to block behind a logger, so it is
// started first and reported afterwards.
func TestChannelDirectionLogsBothEscalationSteps(t *testing.T) {
	var logs syncBuffer
	cancelled := make(chan error, 1)
	f := newTestForwarder(t, abortConnection, cancelled)
	f.logger = slog.New(slog.NewTextHandler(&logs, nil))

	gate := newChannelGate()
	gate.write = make(chan struct{})
	// Close gated too, so the peer never answers and the grace has to expire.
	gate.close = make(chan struct{})
	destination, source, requests, closeSource := forwardTestDirection(t, gate)

	go f.channelDirection(destination, source, requests)
	closeSource()
	close(requests)

	select {
	case err := <-cancelled:
		require.ErrorIs(t, err, errSSHChannelDrainStalled)
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled direction was never aborted")
	}

	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "closing a stalled SSH channel")
	}, 5*time.Second, time.Millisecond,
		"closing a stalled channel left no trace in the daemon log")
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "cancelled the connection")
	}, 5*time.Second, time.Millisecond,
		"taking a whole connection down left no trace in the daemon log")

	gate.releaseAll()
}

// gateFirstChannelConn gates the first channel opened on this connection and
// leaves every later one alone, so one stalled channel and one healthy channel
// share a transport.
type gateFirstChannelConn struct {
	ssh.Conn
	gate *channelGate
	once sync.Once
}

func (c *gateFirstChannelConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	ch, reqs, err := c.Conn.OpenChannel(name, data)
	if err != nil {
		return nil, nil, err
	}
	gated := false
	c.once.Do(func() { gated = true })
	if !gated {
		return ch, reqs, nil
	}
	return gatedChannel{Channel: ch, gate: c.gate}, reqs, nil
}

// forwardTestPeers builds the two connection pairs a forwarder sits between and
// returns, in order: the client whose channel opens travel through the
// forwarder, the forwarder's own downstream and upstream peers, and a snapshot
// of everything the far upstream end has read from the channels it accepted.
//
// The client is returned separately from downstream because downstream is the
// forwarder's own endpoint: a channel opened there travels out to the client
// without the forwarder ever seeing it.
func forwardTestPeers(t *testing.T) (client, downstream, upstream sshPeer, upstreamReceived func() string) {
	t.Helper()
	client, downstream = forwardTestPair(t, nil, nil)
	upstream, far := forwardTestPair(t, nil, nil)
	var mu sync.Mutex
	var received []byte
	// Read every channel the far upstream end is offered, for as long as it is
	// offered any. Delivery is what "the tunnel still works" means, and nothing
	// else on this side of the forwarder would consume these bytes.
	go func() {
		for {
			channel := acceptTestChannel(far)
			if channel == nil {
				return
			}
			go func() {
				chunk := make([]byte, 4096)
				for {
					n, err := channel.Read(chunk)
					mu.Lock()
					received = append(received, chunk[:n]...)
					mu.Unlock()
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return client, downstream, upstream, func() string {
		mu.Lock()
		defer mu.Unlock()
		return string(received)
	}
}

// The forwarder also carries the host's connection, whose transport is the
// reverse tunnel every guest's traffic rides. Cancelling that over one stalled
// channel would end the session for everyone attached.
//
// This one has to go through forwardSSH rather than channelDirection, and the
// two channels have to share the forwarded connection pair. A second direction
// on its own connections proves nothing: the escalation closes *transports*, so
// only a channel on the same transport can show that it survived. And survival
// has to be delivery — channelDirection returns on failure just as readily as
// on success.
func TestHostScopedAbortLeavesTheTunnelWorking(t *testing.T) {
	gate := newChannelGate()
	gate.write = make(chan struct{})
	defer close(gate.write)

	// gateFirstChannelConn wraps the upstream so the first channel the
	// forwarder opens is gated and the rest are untouched.
	client, downstream, upstream, upstreamReceived := forwardTestPeers(t)
	upstream.conn = &gateFirstChannelConn{Conn: upstream.conn, gate: gate}

	forwarded := make(chan error, 1)
	go func() { forwarded <- forwardSSH(t.Context(), downstream, upstream, abortChannel, discardLogger()) }()

	// The stalled channel: opened first, so it gets the gate.
	stalled := openTestChannel(t, client)
	_, err := stalled.Write([]byte("output for a guest that stopped reading"))
	require.NoError(t, err)
	require.NoError(t, stalled.Close()) // source CLOSE, arming the watchdog

	select {
	case <-gate.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled channel was never closed")
	}

	// That CLOSE gets a grace before a connection-scoped forwarder would give
	// up and cancel, taking both transports with it. Outlast the grace before
	// asking whether the transport survived, or the assertions below run in the
	// window where even the wrong scope has not torn anything down yet.
	time.Sleep(2 * sshForwardChannelAbortGrace)

	// The tunnel is still up and still carrying traffic for everyone else.
	live := openTestChannel(t, client)
	const payload = "output for a guest that is still attached"
	_, err = live.Write([]byte(payload))
	require.NoError(t, err, "the shared transport was torn down")

	require.Eventually(t, func() bool {
		return strings.Contains(upstreamReceived(), payload)
	}, 10*time.Second, 10*time.Millisecond,
		"a stalled channel took the tunnel down with it")

	select {
	case err := <-forwarded:
		t.Fatalf("the forwarder exited: %v", err)
	default:
	}
}

func TestChannelDirectionDoesNotAbortADrainingDestination(t *testing.T) {
	cancelled := make(chan error, 1)
	f := newTestForwarder(t, abortConnection, cancelled)

	// Nothing gated: the destination accepts its bytes and closes normally.
	destination, source, requests, closeSource := forwardTestDirection(t, newChannelGate())

	done := make(chan struct{})
	go func() {
		defer close(done)
		f.channelDirection(destination, source, requests)
	}()

	// A direction whose source is still connected is simply idle, however long
	// it stays that way. Outlast both watchdog timers before touching it: one
	// that armed on anything other than source closure would close every live
	// channel on the connection a drain timeout after it opened.
	escalation := f.drainTimeout + f.abortGrace
	select {
	case err := <-cancelled:
		t.Fatalf("a direction whose source was still connected escalated: %v", err)
	case <-time.After(4 * escalation):
	}

	closeSource()
	close(requests)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("an ordinary close should not wait out the drain timeout")
	}
	// Outlast the timers again rather than sampling: the direction returns in
	// microseconds, so a watchdog that escalated regardless of that return
	// would still be counting down at this point.
	select {
	case err := <-cancelled:
		t.Fatalf("an ordinary close escalated: %v", err)
	case <-time.After(4 * escalation):
	}
}
