package capacity

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSilentHandshakeCancellationClosesTransport(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	finished := make(chan error, 1)
	go func() {
		_, err := guestHandshake(ctx, client, "127.0.0.1:22", &ssh.ClientConfig{User: "session", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		finished <- err
	}()
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("silent handshake reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake ignored cancellation")
	}
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := server.Read(make([]byte, 1024)); err == nil {
		t.Fatal("cancelled transport remained open")
	}
}
