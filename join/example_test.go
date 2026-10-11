package join_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/owenthereal/upterm/attach"
	"github.com/owenthereal/upterm/internal/termsize"
	"github.com/owenthereal/upterm/join"
	"golang.org/x/crypto/ssh"
)

// An embedder that is not the command line: it owns the output, the keyboard
// and the relay's key. screen and relayKey stand in for what it has.
func ExampleRun() {
	var screen io.Writer = os.Stdout
	var relayKey ssh.PublicKey // pinned ahead of time
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(screen, format+"\r\n", a...) }

	// A pasted "ssh abc@relay.example.com" fails here instead, with a *TargetError
	// that wraps join.ErrNotATarget and suggests abc@relay.example.com.
	target, err := join.ParseTarget("abc@relay.example.com")
	if err != nil {
		var bad *join.TargetError
		if errors.As(err, &bad) && bad.Suggestion != "" {
			say("did you mean %s?", bad.Suggestion)
		}
		return
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader) // errors elided here and below
	signer, _ := ssh.NewSignerFromKey(key)
	pr, pw := io.Pipe() // the embedder's keyboard writes to pw

	// The embedder's stop ends the run in any phase; Dial and Signers return on it.
	ctx, stop := context.WithCancel(context.Background())
	defer stop() // its close button calls stop too, from any goroutine

	// ConfirmHostKey is nil, so nothing can prompt and the keys are Run's from
	// its start: while no session is ready, Enter cuts a wait short, "~." leaves
	// and Ctrl-C stops the run; once one is, the session gets the keys.
	out := join.Run(ctx, join.Config{
		Target: target,
		Dial: func(ctx context.Context) (net.Conn, error) { // a ws or wss target needs a WebSocket
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target.Host)
		},
		Identity: join.Identity{Signers: func(context.Context) ([]ssh.Signer, func(), error) {
			return []ssh.Signer{signer}, nil, nil
		}},
		// Any key but the pinned one is a changed key, and stops the join.
		CheckHostKey: func(host string, remote net.Addr, k ssh.PublicKey) error {
			if err := ssh.FixedHostKey(relayKey)(host, remote, k); err != nil {
				return fmt.Errorf("%w: %w", join.ErrHostKeyChanged, err)
			}
			return nil
		},
		// A session runs on a copy of this, and writes nothing until it is ready.
		Terminal: &attach.Terminal{Stdout: screen, Pty: &attach.Pty{Term: "xterm-256color"}, Escape: '~'},
		Size:     func() termsize.Size { return termsize.Size{Cols: 120, Rows: 40} },
		Input:    pr,
		// Run starts no attempt and lets no session write while a call runs.
		Events: func(e join.Event) {
			if e.Kind == join.Waiting {
				say("waiting; next attempt at %s", e.Next.Format("15:04:05"))
			}
		},
	})

	// A Read can't be interrupted, so one may still be parked on pr, and would
	// drop the next chunk written. Closing pw ends it; nothing reads pr after.
	_ = pw.Close()

	// A write Run gave up on may still finish after it returns, so screen must
	// tolerate one among its own: a status line, or the last session's output
	// or restore.
	switch out.Kind {
	case join.Exited:
		say("the connection ended with status %d", out.Status)
	case join.Left: // "~." was typed, or pw was closed while Run ran
		say("you left the session")
	case join.Stopped: // stop was called, or Ctrl-C was typed outside a session
		say("stopped")
	case join.Failed:
		// A *join.DeadlineError once a first join's 30 seconds are up, or an error
		// errors.Is matches to a sentinel such as join.ErrKeysRefused.
		say("could not join: %v", out.Err)
	}
}
