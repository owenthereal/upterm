package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/uptermd/command"
	"github.com/stretchr/testify/require"
)

// clearUptermdEnv removes every variable that can reach a decode, so an ambient
// value on a developer's machine cannot change what these tests run. root.go
// binds UPTERMD_* through viper's AutomaticEnv and additionally binds bare
// SENTRY_DSN; PORT and DEBUG reach the decoded struct through flag defaults
// instead, which is why listing the UPTERMD_ prefix alone is not enough.
func clearUptermdEnv(t *testing.T) {
	t.Helper()

	keys := []string{"SENTRY_DSN", "PORT", "DEBUG"}
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "UPTERMD_") {
			keys = append(keys, k)
		}
	}

	for _, k := range keys {
		if old, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		}
		require.NoError(t, os.Unsetenv(k))
	}
}

// freeLoopbackAddr picks a loopback address nothing is listening on. The port is
// released before it is handed back, so in principle something else could take
// it first -- in which case uptermd fails to bind and requireHealthy says so,
// rather than the test hanging or passing having served nothing.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	return addr
}

// healthy reports whether addr answers the websocket front door's /health. It
// dials through a transport of its own rather than http.DefaultClient's: the
// default reads HTTP(S)_PROXY from the environment, which is set in the sandbox
// these tests are run in.
func healthy(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	if err != nil {
		return false
	}

	client := &http.Client{Transport: &http.Transport{}}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode == http.StatusOK
}

// requireHealthy waits until uptermd answers /health, and gives up if it stops
// first. Dialling the port would prove nothing: it is bound before serving
// starts, and the kernel completes the handshake out of the backlog whether or
// not anyone has reached Accept. stopped reports a daemon that is no longer
// running, so the wait fails at once instead of burning the whole deadline.
func requireHealthy(t *testing.T, addr string, stopped <-chan struct{}) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if healthy(addr) {
			return
		}
		select {
		case <-stopped:
			t.Fatalf("uptermd stopped before it served /health on %s", addr)
		case <-time.After(50 * time.Millisecond):
		}
	}

	t.Fatalf("uptermd never served /health on %s", addr)
}

func requireRefused(t *testing.T, addr string) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s still accepts connections after uptermd stopped", addr)
	}
}

// A stop that was asked for must not read as a failure: RunE wraps whatever
// server.Start returns into "failed to start uptermd", and main turns any
// non-nil error into os.Exit(1). A graceful stop exiting 1 tells the supervisor
// the deploy failed.
//
// This is TestMainExitsZeroOnSIGTERM's invariant without the signal, and it is
// the only form of it Windows can run: syscall.SIGTERM exists there but is
// never delivered, so there is no signal for the process to stop on.
func TestExecuteContextReturnsNilWhenContextIsCancelled(t *testing.T) {
	clearUptermdEnv(t)

	wsAddr := freeLoopbackAddr(t)
	ctx, cancel := command.NotifyShutdownSignals(context.Background())
	defer cancel()

	cmd := command.Root()
	// The ssh front door can take an ephemeral port: nothing here connects to
	// it, and node-addr falls back to whatever it binds. The websocket front
	// door cannot -- the test has to reach /health on it, and the command
	// offers no way to read the bound address back out.
	cmd.SetArgs([]string{"--ssh-addr", "127.0.0.1:0", "--ws-addr", wsAddr})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		done <- cmd.ExecuteContext(ctx)
	}()

	requireHealthy(t, wsAddr, stopped)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("uptermd did not stop after its context was cancelled")
	}

	// oklog/run calls its interrupts synchronously before Run returns, so
	// ExecuteContext returning at all means Server.Shutdown has completed and
	// every component has released the listener it owned.
	requireRefused(t, wsAddr)
}
