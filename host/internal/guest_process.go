package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	gssh "charm.land/ssh"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
)

type guestProcessSpec struct {
	Argv, Env []string // Env is complete; nil means empty, not inherited.
	Dir       string
	ReadOnly  bool
}

// runGuestProcess owns one private child. Admission, command selection, presence
// and SSH exit status belong to its caller. In particular, stdin EOF is not
// cancellation and an output copy finishing does not replace the Wait result.
func (h *sessionHandler) runGuestProcess(ctx context.Context, sess gssh.Session, spec guestProcessSpec) (int, error) {
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	if len(spec.Argv) == 0 {
		return 1, errors.New("empty guest command")
	}
	request, windows, isPTY := sess.Pty()
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Dir = spec.Dir
	cmd.Env = guestProcessEnvironment(spec.Env, request.Term, isPTY)
	var terminal PTY
	var pipes *guestPipes
	var err error
	if err = ctx.Err(); err != nil {
		return 1, err
	}
	if isPTY {
		terminal, err = startSessionPty(cmd, termsize.Size{Cols: request.Window.Width, Rows: request.Window.Height})
	} else {
		pipes, err = startGuestPipes(cmd)
		terminal = pipes
	}
	if err != nil {
		return 1, fmt.Errorf("start guest command: %w", err)
	}
	process := &guestProcessOwner{PTY: terminal}
	closer := newPTYCloser(process)
	defer func() { closer.start(); closer.wait(time.Now().Add(time.Second)) }()
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}
	timing := h.timing.orDefault()
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = process.Wait(); close(exited) }()

	// Charm delivers signals synchronously with its session lock held. Keep
	// consuming after the runner returns, until CLOSE/transport loss, so neither
	// Exit nor channel teardown can be starved by a guest's signal requests.
	// Charm v0.4.3 also flushes up to maxSigBufSize (128) pre-registration
	// signals from an uncancelable goroutine. After the request loop ends,
	// empty this mailbox so its bounded remainder can finish without us.
	signals := make(chan gssh.Signal, 128)
	signalsClosed := channelClosed(sess)
	if signalsClosed == nil { // Non-raw internal fixtures have only a context.
		signalsClosed = sess.Context().Done()
	}
	sess.Signals(signals)
	go func() {
		for {
			select {
			case sig, ok := <-signals:
				if !ok {
					return
				}
				if native, ok := guestSignal(sig); ok && !spec.ReadOnly {
					_ = process.Signal(native)
				}
			case <-signalsClosed:
				// raw.closed proves live request delivery has ended. The
				// transport context alone does not establish that boundary.
				for {
					select {
					case _, ok := <-signals:
						if !ok {
							return
						}
					default:
						return
					}
				}
			}
		}
	}()
	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	if isPTY {
		go func() {
			for {
				select {
				case window, ok := <-windows:
					if !ok {
						return
					}
					_ = terminal.Setsize(window.Height, window.Width)
				case <-workCtx.Done():
					return
				case <-exited:
					return
				}
			}
		}()
	}
	if spec.ReadOnly {
		if pipes != nil {
			_ = pipes.stdin.Close()
		}
	} else {
		go func() {
			// The SSH read itself is released by channel teardown. Canceling this
			// adapter lets the runner stop feeding the child before its caller exits.
			_, _ = io.Copy(ptyInputWriter(workCtx, terminal), uio.NewContextReader(workCtx, sess))
			if pipes != nil {
				_ = pipes.stdin.Close()
			}
		}()
	}
	outCtx, cancelOut := context.WithCancel(context.Background())
	defer cancelOut()
	output := newActivityReader(uio.NewContextReader(outCtx, terminal))
	drained := make(chan struct{})
	outputErrors := make(chan error, 2)
	var copies sync.WaitGroup
	copyOutput := func(dst io.Writer, src io.Reader) {
		copies.Add(1)
		go func() {
			defer copies.Done()
			_, err := io.Copy(dst, src)
			if err = ptyError(err); err != nil && outCtx.Err() == nil {
				outputErrors <- err
			}
		}()
	}
	copyOutput(sess, output)
	if pipes != nil {
		copyOutput(sess.Stderr(), uio.NewContextReader(outCtx, pipes.stderr))
	}
	go func() { copies.Wait(); close(drained) }()
	var operationErr error
	select {
	case <-exited:
	case <-ctx.Done():
		operationErr = ctx.Err()
	case operationErr = <-outputErrors:
	}
	if operationErr != nil {
		cancelWork()
		terminateWith(process, closer, exited, timing.hangup, timing.forceCommandStop, logger, spec.Argv[0])
	}
	cancelWork()
	if pipes != nil {
		_ = pipes.stdin.Close()
	}
	if isPTY {
		drainForceCommandOutput(logger, output, drained, nil)
	} else {
		timer := time.NewTimer(forceCommandDrainTimeout)
		select {
		case <-drained:
		case <-timer.C:
		}
		timer.Stop()
	}
	cancelOut()
	closer.start()
	// A read can be canceled locally; an SSH write blocked on the peer's
	// receive window cannot. Close this channel only when the bounded drain
	// failed to release its writers, leaving normal callers free to send status.
	select {
	case <-drained:
	case <-time.After(forceCommandDrainIdle):
		_ = sess.Close()
		if operationErr == nil {
			operationErr = errors.New("guest output did not drain")
		}
		select {
		case <-drained:
		case <-time.After(time.Second):
		}
	}
	select {
	case <-exited:
		code, normal := exitCode(waitErr)
		if _, sig := signalOutcome(waitErr); sig != nil {
			code, normal = 128+*sig, true
		}
		if !normal {
			return 1, errors.Join(operationErr, waitErr)
		}
		if operationErr != nil {
			if code == 0 {
				code = 1
			}
			return code, operationErr
		}
		select {
		case err := <-outputErrors:
			if code == 0 {
				code = 1
			}
			return code, err
		default:
		}
		return code, nil
	default:
		return 1, errors.Join(operationErr, errors.New("guest command did not exit during cleanup"))
	}
}

// guestProcessOwner prevents late SSH signals or escalation steps from using a
// remembered numeric process group after Wait has reported the leader's exit.
// Signal and publication of that observation share a lock; I/O never holds it.
type guestProcessOwner struct {
	PTY
	mu     sync.Mutex
	reaped bool
}

func (p *guestProcessOwner) Wait() error {
	err := p.PTY.Wait()
	p.mu.Lock()
	p.reaped = true
	p.mu.Unlock()
	return err
}
func (p *guestProcessOwner) Signal(sig syscall.Signal) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reaped {
		return os.ErrProcessDone
	}
	return p.PTY.Signal(sig)
}
func (p *guestProcessOwner) Kill() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.reaped {
		return os.ErrProcessDone
	}
	return p.PTY.Kill()
}
func (p *guestProcessOwner) FlushOutput() error {
	if f, ok := p.PTY.(outputFlusher); ok {
		return f.FlushOutput()
	}
	return nil
}

// guestPipes deliberately uses OS files rather than exec's copy goroutines:
// Wait must reap the leader independently of a descendant retaining a stream.
type guestPipes struct {
	cmd                   *exec.Cmd
	stdin, stdout, stderr *os.File
	release               func()
	closeOnce             sync.Once
}

func startGuestPipes(cmd *exec.Cmd) (*guestPipes, error) {
	var owned []*os.File
	failed := true
	defer func() {
		if failed {
			for _, f := range owned {
				_ = f.Close()
			}
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		r, w, err := os.Pipe()
		if err == nil {
			owned = append(owned, r, w)
		}
		return r, w, err
	}
	inR, inW, err := pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := pipe()
	if err != nil {
		return nil, err
	}
	errR, errW, err := pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	release, err := startGuestPipeCommand(cmd)
	if err != nil {
		return nil, err
	}
	_ = inR.Close()
	_ = outW.Close()
	_ = errW.Close()
	failed = false
	return &guestPipes{cmd: cmd, stdin: inW, stdout: outR, stderr: errR, release: release}, nil
}
func (p *guestPipes) Read(b []byte) (int, error)  { return p.stdout.Read(b) }
func (p *guestPipes) Write(b []byte) (int, error) { return p.stdin.Write(b) }
func (p *guestPipes) Setsize(int, int) error      { return nil }
func (p *guestPipes) Redraw() error               { return nil }
func (p *guestPipes) Wait() error                 { return p.cmd.Wait() }
func (p *guestPipes) Kill() error                 { return p.cmd.Process.Kill() }
func (p *guestPipes) Close() error {
	p.closeOnce.Do(func() { _ = p.stdin.Close(); _ = p.stdout.Close(); _ = p.stderr.Close(); p.release() })
	return nil
}
