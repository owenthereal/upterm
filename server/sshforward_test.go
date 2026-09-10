package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

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
	go func() { defer close(stopped); done <- forwardSSH(ctx, downstream, upstream) }()
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
				sender, incoming, func() { aborts <- struct{}{} }, sshRequestAbortGrace, nil)
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
			go func() { done <- forwardSSH(ctx, downstream, upstream) }()
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
