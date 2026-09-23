package host

import (
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// A loopback echo target proves that an accepted forward actually transfers data.
func forwardingTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done; handlers.Wait() })
	return ln.Addr().String()
}

func transferForward(client *ssh.Client, addr string) (net.Conn, error) {
	conn, err := client.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write([]byte("forwarded bytes")); err == nil {
		data := make([]byte, len("forwarded bytes"))
		_, err = io.ReadFull(conn, data)
		if err == nil && string(data) != "forwarded bytes" {
			err = fmt.Errorf("unexpected echo: %q", data)
		}
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func forwardingAdmin(t *testing.T, f *joinTimeoutHost) api.AdminServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("unix://"+f.h.AdminSocketFile, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return api.NewAdminServiceClient(conn)
}

func connectedForwardingGuests(t *testing.T, admin api.AdminServiceClient) []*api.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := admin.GetSession(ctx, &api.GetSessionRequest{})
	require.NoError(t, err)
	return response.ConnectedClients
}

func forwardingCallback(t *testing.T, events <-chan *api.Client) *api.Client {
	t.Helper()
	select {
	case client := <-events:
		return client
	case <-time.After(2 * time.Second):
		t.Fatal("forwarding lifecycle callback missing")
		return nil
	}
}

func TestForwardingPresenceFollowsTransport(t *testing.T) {
	target := forwardingTarget(t)
	f := newJoinTimeoutHost(t)
	f.h.AllowLocalTCPForwarding = true
	joined, left := make(chan *api.Client, 32), make(chan *api.Client, 32)
	f.h.ClientJoinedCallback = func(c *api.Client) { joined <- c }
	f.h.ClientLeftCallback = func(c *api.Client) { left <- c }
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	admin := forwardingAdmin(t, f)
	client := f.guestClient(t)
	require.Empty(t, connectedForwardingGuests(t, admin), "idle authenticated transport is not present")
	select {
	case c := <-joined:
		t.Fatalf("auth-only callback: %v", c)
	case <-time.After(50 * time.Millisecond):
	}

	// Race the first accepted forwards: they must share one transport presence.
	const count = 8
	conns := make([]net.Conn, count)
	errs := make([]error, count)
	var wg sync.WaitGroup
	for i := range conns {
		wg.Add(1)
		go func() { defer wg.Done(); conns[i], errs[i] = transferForward(client, target) }()
	}
	wg.Wait()
	for _, err := range errs {
		require.NoError(t, err)
	}
	guest := forwardingCallback(t, joined)
	require.Equal(t, api.Client_GUEST, guest.Kind)
	require.NotEmpty(t, guest.Id)
	require.NotEmpty(t, guest.PublicKeyFingerprint)
	require.NotEmpty(t, guest.Addr)
	require.Len(t, connectedForwardingGuests(t, admin), 1)
	require.Equal(t, guest.Id, connectedForwardingGuests(t, admin)[0].Id)
	require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
	for _, conn := range conns {
		require.NoError(t, conn.Close())
	}
	select {
	case c := <-left:
		t.Fatalf("channel close removed live transport: %v", c)
	case <-time.After(100 * time.Millisecond):
	}
	require.Len(t, connectedForwardingGuests(t, admin), 1)
	// Reusing the idle transport does not publish a second presence.
	conn, err := transferForward(client, target)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.NoError(t, client.Close())
	require.Equal(t, guest.Id, forwardingCallback(t, left).Id)
	require.Empty(t, connectedForwardingGuests(t, admin))
	select {
	case c := <-joined:
		t.Fatalf("duplicate joined: %v", c)
	case c := <-left:
		t.Fatalf("duplicate left: %v", c)
	case <-time.After(50 * time.Millisecond):
	}
	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestForwardingPresenceDoesNotDisarmJoinTimeout(t *testing.T) {
	for _, registry := range []bool{true, false} {
		t.Run(fmt.Sprintf("session_dir_%t", registry), func(t *testing.T) {
			target := forwardingTarget(t)
			f := newJoinTimeoutHost(t)
			if !registry {
				f.h.AdminSocketFile = filepath.Join(f.root, "admin.sock")
			}
			f.h.AllowLocalTCPForwarding = true
			f.h.JoinTimeout = 800 * time.Millisecond
			f.start(t)
			awaitJoinTimeoutSignal(t, f.ready, "readiness")
			client := f.guestClient(t)
			conn, err := transferForward(client, target)
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()
			awaitJoinTimeoutSignal(t, f.joined, "forwarding presence")
			require.Len(t, connectedForwardingGuests(t, forwardingAdmin(t, f)), 1)
			if registry {
				require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
			}
			require.NoError(t, f.result(t))
			if registry {
				require.Equal(t, sessiondir.ReasonJoinTimeout, f.record(t).Reason)
				require.True(t, f.record(t).FirstGuestJoinedAt.IsZero())
			}
		})
	}
}

func TestUnacceptedForwardingDoesNotPublishPresence(t *testing.T) {
	for _, mode := range []string{"denied", "malformed", "failed_dial"} {
		t.Run(mode, func(t *testing.T) {
			f := newJoinTimeoutHost(t)
			f.h.AllowLocalTCPForwarding = mode != "denied"
			f.start(t)
			awaitJoinTimeoutSignal(t, f.ready, "readiness")
			client := f.guestClient(t)
			if mode == "malformed" {
				_, _, err := client.OpenChannel("direct-tcpip", []byte{0})
				require.Error(t, err)
			} else {
				target := forwardingTarget(t)
				if mode == "failed_dial" {
					ln, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					target = ln.Addr().String()
					require.NoError(t, ln.Close())
				}
				_, err := client.Dial("tcp", target)
				require.Error(t, err)
			}
			require.Empty(t, connectedForwardingGuests(t, forwardingAdmin(t, f)))
			require.NoError(t, client.Close())
			select {
			case <-f.joined:
				t.Fatal("unaccepted forward joined")
			case <-f.left:
				t.Fatal("unaccepted forward left")
			case <-time.After(100 * time.Millisecond):
			}
			f.finish(t, "0")
			require.NoError(t, f.result(t))
		})
	}
}

func TestJoinTimeoutAcceptedSFTPDisarmsDeadline(t *testing.T) {
	f := newJoinTimeoutHost(t)
	f.h.JoinTimeout = 200 * time.Millisecond
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	client := f.guestClient(t)
	transfer, err := sftp.NewClient(client)
	require.NoError(t, err)
	awaitJoinTimeoutSignal(t, f.joined, "SFTP join")
	require.NoError(t, transfer.Close())
	awaitJoinTimeoutSignal(t, f.left, "SFTP left")
	select {
	case err := <-f.done:
		t.Fatalf("SFTP did not disarm deadline: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	require.False(t, f.record(t).FirstGuestJoinedAt.IsZero())
	f.finish(t, "0")
	require.NoError(t, f.result(t))
}

func TestForwardingDisconnectDuringConcurrentOpens(t *testing.T) {
	target := forwardingTarget(t)
	f := newJoinTimeoutHost(t)
	f.h.AllowLocalTCPForwarding = true
	joined, left := make(chan *api.Client, 32), make(chan *api.Client, 32)
	f.h.ClientJoinedCallback = func(c *api.Client) { joined <- c }
	f.h.ClientLeftCallback = func(c *api.Client) { left <- c }
	f.start(t)
	awaitJoinTimeoutSignal(t, f.ready, "readiness")
	admin := forwardingAdmin(t, f)
	ids := make(map[string]bool)
	for range 12 {
		client := f.guestClient(t)
		// Dial returning means Accept succeeded; disconnect without waiting for the
		// asynchronous presence callback, while more channel handlers are running.
		first, err := client.Dial("tcp", target)
		require.NoError(t, err)
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := client.Dial("tcp", target)
				if err == nil {
					_ = conn.Close()
				}
			}()
		}
		require.NoError(t, client.Close())
		_ = first.Close()
		wg.Wait()
		guest := forwardingCallback(t, joined)
		require.False(t, ids[guest.Id], "each transport needs its own lifecycle ID")
		ids[guest.Id] = true
		require.Equal(t, guest.Id, forwardingCallback(t, left).Id)
		require.Empty(t, connectedForwardingGuests(t, admin))
	}
	f.finish(t, "0")
	require.NoError(t, f.result(t))
	require.Empty(t, joined)
	require.Empty(t, left)
}

func TestForwardingLifecycleReconcilesLeftBeforePresenceWithoutJoining(t *testing.T) {
	repo := internal.NewClientRepo()
	var events []string
	lifecycle := &clientLifecycle{
		repo: repo, pendingLeft: make(map[string]struct{}),
		onGuestJoin: func(*api.Client) error { t.Error("forwarding disarmed first-guest deadline"); return nil },
		onJoined:    func(*api.Client) { events = append(events, "joined") },
		onLeft:      func(*api.Client) { events = append(events, "left") },
	}
	client := &api.Client{Id: "quick-forward", Kind: api.Client_GUEST}
	lifecycle.left(client.Id)
	lifecycle.joined(client, false)
	require.Empty(t, repo.Clients())
	require.Empty(t, lifecycle.pendingLeft)
	require.Equal(t, []string{"joined", "left"}, events)
}
