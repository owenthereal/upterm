package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// requireStockSSHBinary skips unless a system ssh binary is usable here.
func requireStockSSHBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stock ssh client case is POSIX-only")
	}
	path, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no ssh binary on PATH")
	}
	return path
}

// stockSSHClientArgs isolates the invocation from the developer's environment.
// -F os.DevNull is the part that matters: a wildcard Host * block carrying
// ProxyCommand, ProxyJump or ControlMaster would otherwise redirect this
// connection. OpenSSH still reads /etc/ssh/ssh_config and gives no way to
// suppress it, so the isolation is good rather than total. -T keeps the session
// pty-free: this server answers requests without allocating one, and a pty
// would add CR translation between the bytes written and the bytes asserted.
func stockSSHClientArgs(addr string) []string {
	host, port, _ := net.SplitHostPort(addr)
	return []string{
		"-T",
		"-F", os.DevNull,
		"-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=" + os.DevNull,
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=none,password",
		"-o", "LogLevel=ERROR",
		"test@" + host,
		"irrelevant-command",
	}
}

// forwardTestStockClientHost accepts one real ssh client on a loopback
// listener, forwards it through forwardSSH, and returns the address to dial
// plus the peer standing in for the host at the far end.
func forwardTestStockClientHost(t *testing.T) (string, sshPeer) {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	upstream, host := forwardTestPair(t, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Error("forwarder workers did not drain")
		}
	})

	go func() {
		defer close(stopped)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		serverConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			_ = conn.Close()
			return
		}
		// A stock OpenSSH client is a guest, so its connection is the abort unit.
		_ = forwardSSH(ctx, sshPeer{serverConn, channels, requests}, upstream, abortConnection)
	}()

	return listener.Addr().String(), host
}

// TestSSHForwardStockSSHClientReadsPastExitStatus pins that a real OpenSSH
// client keeps delivering channel data it receives after exit-status, through
// forwardSSH.
//
// This is the discriminating version of the functional case in
// ftests/proxy_test.go. That one writes a large volume and exits immediately,
// which shows OpenSSH works in a realistic scenario but never constructs the
// race: nothing there forces output to be undelivered at the instant the
// status is processed, so a client that quit on exit-status could still pass.
//
// Here the host withholds the trailing bytes until the client has demonstrably
// processed the status. exit-status is followed by an unknown channel request
// with want_reply; OpenSSH answers unknown requests with CHANNEL_FAILURE, and
// channel requests are processed in order, so that reply is proof the client
// consumed the status. Only then does the host send the tail. A client that
// treated exit-status as end-of-session drops the tail and fails the assertion
// below; one that quit outright never answers the probe and trips its timeout.
//
// Detection power was measured rather than assumed: withholding the tail write
// makes this fail with "client output 4096 bytes, want 8192 ... tail present:
// false", which is the signature a dropping client would produce. That the head
// still arrives in that run is also what proves the ssh binary really connected
// and relayed through forwardSSH, rather than the case passing vacuously.
func TestSSHForwardStockSSHClientReadsPastExitStatus(t *testing.T) {
	const wantCode = 42

	sshPath := requireStockSSHBinary(t)
	addr, host := forwardTestStockClientHost(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, sshPath, stockSSHClientArgs(addr)...)
	// Hold the client's stdin open so it does not send EOF and end the session
	// before the host has finished its sequence. Nothing is ever written.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	head := bytes.Repeat([]byte("h"), 4096)
	tail := bytes.Repeat([]byte("t"), 4096)

	sequence := make(chan error, 1)
	go func() { sequence <- driveStockClientSession(host, head, tail, wantCode) }()

	if err := forwardTestReceive(t, sequence); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("host sequence failed: %v; ssh stderr: %s", err, stderr.String())
	}

	runErr := cmd.Wait()
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Fatalf("stock ssh client timed out: %v; stderr: %s", ctxErr, stderr.String())
	}

	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != wantCode {
		t.Fatalf("ssh exited with %v, want status %d; stderr: %s", runErr, wantCode, stderr.String())
	}

	got := stdout.Bytes()
	if want := append(append([]byte{}, head...), tail...); !bytes.Equal(got, want) {
		t.Fatalf("client output %d bytes, want %d (head %d + tail %d); tail present: %t",
			len(got), len(want), len(head), len(tail),
			bytes.Contains(got, tail))
	}
}

// driveStockClientSession plays the host side: answer the session's setup
// requests, send head, send exit-status, prove the client processed it, then
// send tail and close.
func driveStockClientSession(host sshPeer, head, tail []byte, code int) error {
	newChannel, ok := <-host.channels
	if !ok {
		return errors.New("client opened no channel")
	}
	if newChannel.ChannelType() != "session" {
		return fmt.Errorf("channel type %q, want session", newChannel.ChannelType())
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer func() { _ = channel.Close() }()

	// Answer setup requests until the client asks to run something. Replying
	// to exec/shell is what makes ssh start relaying the session.
	started := false
	for !started {
		request, ok := <-requests
		if !ok {
			return errors.New("client closed requests before starting a command")
		}
		switch request.Type {
		case "exec", "shell", "subsystem":
			started = true
		}
		if request.WantReply {
			if err := request.Reply(true, nil); err != nil {
				return err
			}
		}
	}
	go ssh.DiscardRequests(requests)

	if _, err := channel.Write(head); err != nil {
		return fmt.Errorf("writing head: %w", err)
	}
	status := struct{ Status uint32 }{uint32(code)}
	if _, err := channel.SendRequest("exit-status", false, ssh.Marshal(&status)); err != nil {
		return fmt.Errorf("sending exit-status: %w", err)
	}

	// The probe is the whole point. OpenSSH answers an unknown channel request
	// with CHANNEL_FAILURE, and RFC 4254 §4 keeps channel requests in order, so
	// receiving this reply proves the client already handled the exit-status
	// ahead of it. ok is false by design; only the reply's arrival matters.
	if _, err := channel.SendRequest("status-observed@upterm.test", true, nil); err != nil {
		return fmt.Errorf("client did not answer the post-status probe: %w", err)
	}

	if _, err := channel.Write(tail); err != nil {
		return fmt.Errorf("writing tail after exit-status: %w", err)
	}
	return channel.Close()
}
