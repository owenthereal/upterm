package attach

import (
	"bytes"
	gssh "charm.land/ssh"
	"context"
	"fmt"
	"github.com/owenthereal/upterm/internal/termsize"
	uio "github.com/owenthereal/upterm/io"
	"github.com/owenthereal/upterm/upterm"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type approvalTestReview struct {
	updates chan upterm.ApprovalState
	answers chan upterm.ApprovalAnswer
}

func (r *approvalTestReview) Updates() <-chan upterm.ApprovalState { return r.updates }
func (r *approvalTestReview) Answer(ctx context.Context, a upterm.ApprovalAnswer) error {
	select {
	case r.answers <- a:
	case <-ctx.Done():
	}
	return nil
}
func approvalTestState(id string) upterm.ApprovalState {
	return upterm.ApprovalState{Revision: 1, Pending: 1, Current: &upterm.ApprovalRequest{ID: id, Capability: "exec", Operation: "exec", Fingerprint: "SHA256:guest", Subjects: [][]byte{[]byte("echo hello")}, DeadlineUnixMilli: time.Now().Add(time.Minute).UnixMilli()}}
}
func approvalTestOutput(w io.Writer) *output {
	return &output{w: w, modes: uio.NewModeTracker(), turn: make(chan struct{}, 1), released: make(chan struct{}), statusClosing: make(chan struct{}), failed: make(chan struct{})}
}
func approvalTestCode(t *testing.T, s string) string {
	t.Helper()
	i := strings.LastIndex(s, "upterm: d ")
	require.GreaterOrEqual(t, i, 0, s)
	return s[i+10 : i+14]
}
func approvalTestRun(t *testing.T, w io.Writer) (*approvalTestReview, *io.PipeWriter, *syncSink, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &approvalTestReview{make(chan upterm.ApprovalState, 8), make(chan upterm.ApprovalAnswer, 8)}
	pr, pw := io.Pipe()
	program := &syncSink{}
	o := approvalTestOutput(w)
	done := make(chan struct{})
	go func() {
		defer close(done)
		term := Terminal{Stdin: pr, Escape: '~', Approvals: r}
		term.forwardInput(ctx, nil, program, o, terminalLimits{}.orDefault(), slog.New(slog.DiscardHandler))
	}()
	return r, pw, program, func() { cancel(); _ = pw.Close(); <-done; o.closeStatus() }
}

func TestApprovalRenderBeforeAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &approvalGateSink{entered: make(chan string, 8), release: make(chan struct{})}
		r, pw, _, stop := approvalTestRun(t, sink)
		defer stop()
		r.updates <- approvalTestState("first")
		synctest.Wait()
		// Release the notification, then stall the full review write.
		<-sink.entered
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		display := <-sink.entered
		code := approvalTestCode(t, display)
		_, _ = pw.Write([]byte("g " + code + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers, "display write is still in flight")
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("c " + code + "\r"))
		synctest.Wait()
		require.Len(t, r.answers, 1)
		require.Equal(t, upterm.ApprovalAnswer{ID: "first", Decision: "connection"}, <-r.answers)
		close(sink.release)
	})
}

type approvalGateSink struct {
	entered chan string
	release chan struct{}
}

func (s *approvalGateSink) Write(p []byte) (int, error) {
	s.entered <- string(p)
	<-s.release
	return len(p), nil
}

func TestApprovalReviewQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, _, stop := approvalTestRun(t, sink)
		defer stop()
		state := approvalTestState("first")
		deadline := state.Current.DeadlineUnixMilli
		r.updates <- state
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		code := approvalTestCode(t, sink.String())
		_, _ = pw.Write([]byte("g " + code[:2]))
		synctest.Wait()
		next := approvalTestState("second")
		next.Revision = 2
		r.updates <- next
		synctest.Wait()
		_, _ = pw.Write([]byte(code[2:] + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers)
		nextCode := approvalTestCode(t, sink.String())
		require.NotEqual(t, code, nextCode)
		_, _ = pw.Write([]byte("g " + code + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("d " + nextCode + "\r"))
		synctest.Wait()
		require.Equal(t, upterm.ApprovalAnswer{ID: "second", Decision: "deny"}, <-r.answers)
		state.Revision = 3
		r.updates <- state
		synctest.Wait()
		_, _ = pw.Write([]byte("\x1b"))
		time.Sleep(51 * time.Millisecond)
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		require.Equal(t, deadline, state.Current.DeadlineUnixMilli)
		require.NotEqual(t, code, approvalTestCode(t, sink.String()))
	})
}
func TestApprovalKeepsProgramIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		r.updates <- approvalTestState("first")
		synctest.Wait()
		_, _ = pw.Write([]byte("program\r~ag FAKE\r"))
		synctest.Wait()
		require.Equal(t, "program\r", program.String())
		code := approvalTestCode(t, sink.String())
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("\x1b]52;c;g " + code + "\r\a\x1b[200~g " + code + "\r\x1b[201~"))
		synctest.Wait()
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("c " + code + "\r"))
		synctest.Wait()
		require.Len(t, r.answers, 1)
		require.NotContains(t, program.String(), "c "+code)
	})
}

// A full tuple is displayed losslessly, including invalid bytes, literal escape
// text and Unicode controls. An unidentified peer never gets a guest promise.
func TestApprovalVisibleSubjects(t *testing.T) {
	state := approvalTestState("bytes")
	state.Current.Fingerprint = "key\n\x1b\u202e"
	state.Current.Operation = "rename"
	state.Current.Capability = "sftp"
	state.Current.Subjects = [][]byte{{0xff}, []byte("\ufffd\\xff\n\x1b\u202e")}
	lines := strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Contains(t, lines, `subject[0] = "\xff"`)
	require.Contains(t, lines, `subject[1] = "\ufffd\\xff\n\x1b\u202e"`)
	require.Contains(t, lines, `guest "key\n\x1b\u202e"`)
	require.NotContains(t, lines, "\x1b")
	state.Current.Fingerprint = ""
	lines = strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Contains(t, lines, "unidentified")
	require.NotContains(t, lines, "g ABCD")
	state.Current.Subjects = [][]byte{bytes.Repeat([]byte{0xff}, 4096), bytes.Repeat([]byte{0xfe}, 4096)}
	lines = strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Equal(t, 4096, strings.Count(lines, `\xff`))
	require.Equal(t, 4096, strings.Count(lines, `\xfe`))
}

func TestApprovalDisplayOutcomes(t *testing.T) {
	for _, kind := range []string{"short", "failed", "OSC", "DCS", "CSI", "UTF8"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &approvalOutcomeSink{kind: kind}
				o := approvalTestOutput(sink)
				prefix := map[string]string{"OSC": "\x1b]52;c;", "DCS": "\x1bP", "CSI": "\x1b[?2004", "UTF8": "\xe2\x80"}[kind]
				if prefix != "" {
					require.NoError(t, copyOutput(strings.NewReader(prefix), o))
				}
				terminal := &Terminal{Escape: '~'}
				r := newTerminalReview(terminal, o, terminalLimits{}.orDefault(), slog.New(slog.DiscardHandler))
				defer r.close()
				defer o.closeStatus()
				r.state = approvalTestState("first")
				r.enter()
				synctest.Wait()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				done := <-r.display
				require.NotEqual(t, localCompleted, done.result)
				if prefix != "" {
					require.NotContains(t, sink.String(), "upterm: guest")
				}
			})
		})
	}
}

type approvalOutcomeSink struct {
	syncSink
	kind string
}

func (s *approvalOutcomeSink) Write(p []byte) (int, error) {
	if s.kind == "short" {
		return len(p) - 1, nil
	}
	if s.kind == "failed" {
		return 0, io.ErrClosedPipe
	}
	return s.syncSink.Write(p)
}

func TestApprovalConfirmationSplits(t *testing.T) {
	for split := 0; split <= 7; split++ {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &syncSink{}
				r, pw, _, stop := approvalTestRun(t, sink)
				defer stop()
				r.updates <- approvalTestState("first")
				synctest.Wait()
				_, _ = pw.Write([]byte("~a"))
				synctest.Wait()
				confirmation := "g " + approvalTestCode(t, sink.String()) + "\r"
				_, _ = pw.Write([]byte(confirmation[:split]))
				synctest.Wait()
				_, _ = pw.Write([]byte(confirmation[split:]))
				synctest.Wait()
				require.Len(t, r.answers, 1)
				require.Equal(t, "first", (<-r.answers).ID)
			})
		})
	}
}

func TestApprovalLateSequenceAndReentry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		state := approvalTestState("first")
		r.updates <- state
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		old := approvalTestCode(t, sink.String())
		_, _ = pw.Write([]byte("\x1b"))
		time.Sleep(51 * time.Millisecond)
		synctest.Wait()
		_, _ = pw.Write([]byte("]52;c;g " + old + "\r~a"))
		synctest.Wait()
		require.Empty(t, r.answers)
		require.NotContains(t, sink.String()[strings.LastIndex(sink.String(), "upterm: guest"):], "new request")
		_, _ = pw.Write([]byte("\a~a"))
		synctest.Wait()
		code := approvalTestCode(t, sink.String())
		require.NotEqual(t, old, code)
		require.Contains(t, program.String(), "\x1b]52;c;g "+old+"\r~a\a")
		_, _ = pw.Write([]byte("c " + code + "\r"))
		synctest.Wait()
		require.Len(t, r.answers, 1)
	})
}

func TestApprovalExpiryAndGuestResolution(t *testing.T) {
	for _, end := range []string{"expiry", "guest-wide", "primary-loss"} {
		t.Run(end, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &syncSink{}
				r, pw, _, stop := approvalTestRun(t, sink)
				defer stop()
				state := approvalTestState("first")
				r.updates <- state
				synctest.Wait()
				_, _ = pw.Write([]byte("~a"))
				synctest.Wait()
				code := approvalTestCode(t, sink.String())
				_, _ = pw.Write([]byte("g " + code[:2]))
				synctest.Wait()
				if end == "expiry" {
					time.Sleep(61 * time.Second)
				} else if end == "guest-wide" {
					r.updates <- upterm.ApprovalState{Revision: 2}
				} else {
					close(r.updates)
				}
				synctest.Wait()
				_, _ = pw.Write([]byte(code[2:] + "\r"))
				synctest.Wait()
				require.Empty(t, r.answers)
			})
		})
	}
}

func TestApprovalOutputContinuesAndStatusWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		sink := &syncSink{}
		o := approvalTestOutput(sink)
		review := &approvalTestReview{make(chan upterm.ApprovalState, 8), make(chan upterm.ApprovalAnswer, 8)}
		pr, pw := io.Pipe()
		defer pw.Close()
		lookup := make(chan struct{})
		asked := make(chan struct{})
		done := make(chan struct{})
		term := Terminal{Stdin: pr, Escape: '~', Approvals: review, Status: func(ctx context.Context) []string {
			close(asked)
			select {
			case <-lookup:
			case <-ctx.Done():
			}
			return []string{"STATUS"}
		}}
		go func() {
			defer close(done)
			term.forwardInput(ctx, nil, io.Discard, o, terminalLimits{}.orDefault(), slog.New(slog.DiscardHandler))
		}()
		review.updates <- approvalTestState("first")
		synctest.Wait()
		_, _ = pw.Write([]byte("~?"))
		<-asked
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		code := approvalTestCode(t, sink.String())
		require.NoError(t, copyOutput(strings.NewReader("PROGRAM DURING REVIEW"), o))
		require.Contains(t, sink.String(), "PROGRAM DURING REVIEW")
		close(lookup)
		synctest.Wait()
		_, _ = pw.Write([]byte("c " + code + "\r"))
		synctest.Wait()
		require.Len(t, review.answers, 1)
		cancel()
		_ = pw.Close()
		<-done
		o.closeStatus()
	})
}

func TestApprovalAnswerBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		calls := 0
		control := newApprovalControl(func(string, bool, []byte) (bool, []byte, error) {
			calls++
			close(entered)
			<-release
			return true, nil, nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- control.Answer(ctx, upterm.ApprovalAnswer{ID: "first", Decision: "deny"}) }()
		<-entered
		time.Sleep(2 * time.Second)
		synctest.Wait()
		require.ErrorIs(t, <-done, context.DeadlineExceeded)
		require.Error(t, control.Answer(context.Background(), upterm.ApprovalAnswer{ID: "next", Decision: "deny"}))
		require.Equal(t, 1, calls)
		close(release)
		synctest.Wait()
	})
}

func TestApprovalFailedDisplayNeverArms(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &approvalCaptureFailure{short: short}
				review, pw, _, stop := approvalTestRun(t, sink)
				defer stop()
				review.updates <- approvalTestState("first")
				synctest.Wait()
				_, _ = pw.Write([]byte("~a"))
				synctest.Wait()
				code := approvalTestCode(t, sink.String())
				_, _ = pw.Write([]byte("g " + code + "\r"))
				synctest.Wait()
				require.Empty(t, review.answers, "an unsuccessful display cannot arm input")
			})
		})
	}
}

type approvalCaptureFailure struct {
	syncSink
	short bool
}

func (s *approvalCaptureFailure) Write(p []byte) (int, error) {
	s.syncSink.Write(p)
	if s.short {
		return len(p) - 1, nil
	}
	return 0, io.ErrClosedPipe
}

func TestApprovalSameReadFraming(t *testing.T) {
	for _, framing := range []struct{ start, end string }{{"\x1b[200~", "\x1b[201~"}, {"\x1b]52;c;", "\a"}, {"\x1bP", "\x1b\\"}, {"\x1b_", "\x1b\\"}} {
		for split := 1; split <= len(framing.start); split++ {
			t.Run(fmt.Sprintf("%q/%d", framing.start, split), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sink := &syncSink{}
					r, pw, _, stop := approvalTestRun(t, sink)
					defer stop()
					r.updates <- approvalTestState("first")
					synctest.Wait()
					_, _ = pw.Write([]byte("~a" + framing.start[:split]))
					synctest.Wait()
					code := approvalTestCode(t, sink.String())
					_, _ = pw.Write([]byte(framing.start[split:] + "g " + code + "\r" + framing.end))
					synctest.Wait()
					require.Empty(t, r.answers)
					_, _ = pw.Write([]byte("c " + code + "\r"))
					synctest.Wait()
					require.Len(t, r.answers, 1)
				})
			})
		}
	}
}

func TestApprovalMalformedSequence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, _, stop := approvalTestRun(t, sink)
		defer stop()
		r.updates <- approvalTestState("first")
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		code := approvalTestCode(t, sink.String())
		_, _ = pw.Write([]byte("\x1b[\x1b]52;c;"))
		synctest.Wait()
		_, _ = pw.Write([]byte("\rg " + code + "\r\a"))
		synctest.Wait()
		require.Empty(t, r.answers)
	})
}

func TestApprovalEncodedEscape(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		r.updates <- approvalTestState("first")
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		_, _ = pw.Write([]byte("\x1b[27u"))
		synctest.Wait()
		_, _ = pw.Write([]byte("program\r"))
		synctest.Wait()
		require.Equal(t, "program\r", program.String())
	})
}

func TestApprovalStaleDisplayCompletion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &approvalGateSink{entered: make(chan string, 8), release: make(chan struct{})}
		review, pw, _, stop := approvalTestRun(t, sink)
		defer stop()
		review.updates <- approvalTestState("first")
		synctest.Wait()
		<-sink.entered
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		first := approvalTestCode(t, <-sink.entered)
		second := approvalTestState("second")
		second.Revision = 2
		review.updates <- second
		synctest.Wait()
		sink.release <- struct{}{}
		synctest.Wait()
		code := approvalTestCode(t, <-sink.entered)
		_, _ = pw.Write([]byte("c " + first + "\rc " + code + "\r"))
		synctest.Wait()
		require.Empty(t, review.answers, "the first completion must not arm the still-undisplayed replacement")
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("c " + code + "\r"))
		synctest.Wait()
		require.Len(t, review.answers, 1)
		require.Equal(t, "second", (<-review.answers).ID)
		close(sink.release)
	})
}

func TestApprovalControlCoalesces(t *testing.T) {
	control := newApprovalControl(nil)
	for revision := uint64(1); revision <= 100; revision++ {
		state := approvalTestState("first")
		state.Revision = revision
		payload, err := upterm.EncodeApprovalState(state)
		require.NoError(t, err)
		require.True(t, control.accept(payload))
	}
	require.Len(t, control.updates, 1)
	require.Equal(t, uint64(100), (<-control.Updates()).Revision)
	require.False(t, control.accept([]byte(`{"Revision":101,"Pending":1,"Current":{"ID":"x","Capability":"exec","Operation":"exec","Subjects":[[97]],"DeadlineUnixMilli":1}}`)))
	require.Empty(t, control.updates)
}

func TestApprovalSuspendAndDetach(t *testing.T) {
	program := &syncSink{}
	door := serveDoor(t, func(s gssh.Session) {
		_, wins, _ := s.Pty()
		go func() {
			for range wins {
			}
		}()
		_, _ = io.WriteString(s, "READY")
		_, _ = io.Copy(program, s)
	})
	review := &approvalTestReview{make(chan upterm.ApprovalState, 8), make(chan upterm.ApprovalAnswer, 8)}
	pr, pw := io.Pipe()
	defer pw.Close()
	sink := &syncSink{}
	suspended := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	done := make(chan Result, 1)
	terminal := &Terminal{Stdin: pr, Stdout: sink, Pty: &Pty{Term: "xterm"}, Escape: '!', Approvals: review, Suspend: func() (termsize.Size, bool) { suspended <- struct{}{}; return termsize.Default, true }, Logger: slog.New(slog.DiscardHandler)}
	client := dialDoor(t, door)
	go func() {
		res, err := terminal.Run(ctx, client, time.Now().Add(testTimeout))
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- res
	}()
	review.updates <- approvalTestState("first")
	waitFor(t, func() bool { return strings.Contains(sink.String(), "pending") }, "notification")
	_, err := pw.Write([]byte("!a"))
	require.NoError(t, err)
	waitFor(t, func() bool { return strings.Contains(sink.String(), "upterm: d ") }, "review")
	oldCode := approvalTestCode(t, sink.String())
	_, err = pw.Write([]byte("!\x1a"))
	require.NoError(t, err)
	select {
	case <-suspended:
	case <-ctx.Done():
		t.Fatal("suspend blocked")
	}
	_, err = pw.Write([]byte("program\r!a"))
	require.NoError(t, err)
	waitFor(t, func() bool { return strings.Count(sink.String(), "upterm: d ") >= 2 }, "re-entry")
	code := approvalTestCode(t, sink.String())
	require.NotEqual(t, oldCode, code)
	_, err = pw.Write([]byte("g " + oldCode + "\r!."))
	require.NoError(t, err)
	res := awaitResult(t, done)
	require.Equal(t, Detached, res.Reason)
	require.Empty(t, review.answers)
	require.Contains(t, program.String(), "program\r")
}

func TestApprovalExpiryAdvancesReview(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		first := approvalTestState("first")
		first.Current.DeadlineUnixMilli = time.Now().Add(time.Second).UnixMilli()
		r.updates <- first
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		old := approvalTestCode(t, sink.String())
		time.Sleep(2 * time.Second)
		synctest.Wait()
		_, _ = pw.Write([]byte("g " + old + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers)
		require.NotContains(t, program.String(), "g "+old)
		next := approvalTestState("next")
		next.Revision = 2
		r.updates <- next
		synctest.Wait()
		require.Contains(t, sink.String(), "upterm: d ")
		code := approvalTestCode(t, sink.String())
		require.NotEqual(t, old, code)
		_, _ = pw.Write([]byte("c " + code + "\r"))
		synctest.Wait()
		require.Len(t, r.answers, 1)
	})
}

func TestApprovalPrimaryLossRetiresRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, _, stop := approvalTestRun(t, sink)
		defer stop()
		r.updates <- approvalTestState("first")
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		before := strings.Count(sink.String(), "upterm: d ")
		close(r.updates)
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		require.Equal(t, before, strings.Count(sink.String(), "upterm: d "))
	})
}

func TestApprovalInputEpoch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		review := &approvalTestReview{make(chan upterm.ApprovalState, 1), make(chan upterm.ApprovalAnswer, 1)}
		r := newTerminalReview(&Terminal{Escape: '~', Approvals: review}, approvalTestOutput(io.Discard), terminalLimits{}.orDefault(), slog.New(slog.DiscardHandler))
		defer r.close()
		r.ctx = context.Background()
		r.state = approvalTestState("shown")
		r.active = true
		r.armed = true
		r.code = "ABCD"
		r.epoch.Store(2)
		filter := NewEscapeFilter('~', false, WithApproval())
		_, _ = r.input(approvalRead{p: []byte("g ABCD\r"), epoch: 1}, filter)
		synctest.Wait()
		require.Empty(t, review.answers, "queued before display completion")
		_, _ = r.input(approvalRead{p: []byte("c ABCD\r"), epoch: 2}, filter)
		synctest.Wait()
		require.Len(t, review.answers, 1)
		require.Equal(t, "shown", (<-review.answers).ID)
	})
}

func TestApprovalEscapeBeforeDisplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &approvalGateSink{entered: make(chan string, 8), release: make(chan struct{})}
		review, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		defer close(sink.release)
		review.updates <- approvalTestState("first")
		synctest.Wait()
		<-sink.entered
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		<-sink.entered
		_, _ = pw.Write([]byte("\x1b[27u"))
		synctest.Wait()
		_, _ = pw.Write([]byte("program\r"))
		synctest.Wait()
		require.Equal(t, "program\r", program.String())
		require.Empty(t, review.answers)
	})
}

func TestApprovalKittyReleaseEvents(t *testing.T) {
	for _, mode := range []string{"separate-reads", "press-release-pair", "whole-confirmation"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &syncSink{}
				review, pw, program, stop := approvalTestRun(t, sink)
				defer stop()
				review.updates <- approvalTestState("first")
				synctest.Wait()
				_, _ = pw.Write([]byte("~a"))
				synctest.Wait()
				confirmation := "g " + approvalTestCode(t, sink.String()) + "\r"
				var whole string
				for _, key := range []byte(confirmation) {
					press := fmt.Sprintf("\x1b[%d;1:1u", key)
					release := fmt.Sprintf("\x1b[%d;1:3u", key)
					switch mode {
					case "separate-reads":
						_, _ = pw.Write([]byte(press))
						synctest.Wait()
						_, _ = pw.Write([]byte(release))
						synctest.Wait()
					case "press-release-pair":
						_, _ = pw.Write([]byte(press + release))
						synctest.Wait()
					case "whole-confirmation":
						whole += press + release
					}
				}
				if whole != "" {
					_, _ = pw.Write([]byte(whole))
					synctest.Wait()
				}
				require.Len(t, review.answers, 1)
				require.Equal(t, upterm.ApprovalAnswer{ID: "first", Decision: "guest"}, <-review.answers)
				require.Empty(t, program.String())
			})
		})
	}
}

func TestApprovalSequenceEpochBoundary(t *testing.T) {
	for _, entryRemainder := range []bool{false, true} {
		t.Run(fmt.Sprint(entryRemainder), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &approvalGateSink{entered: make(chan string, 8), release: make(chan struct{})}
				review, pw, program, stop := approvalTestRun(t, sink)
				defer stop()
				defer close(sink.release)
				review.updates <- approvalTestState("first")
				synctest.Wait()
				<-sink.entered
				sink.release <- struct{}{}
				synctest.Wait()
				entry := "~a"
				if entryRemainder {
					entry += "\x1b[103"
				}
				_, _ = pw.Write([]byte(entry))
				synctest.Wait()
				code := approvalTestCode(t, <-sink.entered)
				if !entryRemainder {
					_, _ = pw.Write([]byte("\x1b[103"))
					synctest.Wait()
				}
				sink.release <- struct{}{}
				synctest.Wait()
				_, _ = pw.Write([]byte("u " + code + "\r"))
				synctest.Wait()
				require.Empty(t, review.answers, "a pre-display key prefix cannot acquire the completion read's epoch")
				require.Empty(t, program.String())
				_, _ = pw.Write([]byte("c " + code + "\r"))
				synctest.Wait()
				require.Len(t, review.answers, 1)
				require.Equal(t, "first", (<-review.answers).ID)
			})
		})
	}
}

func TestApprovalEntryReplySuffix(t *testing.T) {
	for _, reply := range []string{"\x1b[12;34R", "\x1b]52;c;Z29vZA==\a", "\x1bP1$rvalue\x1b\\", "\x1b_reply\x1b\\"} {
		for split := 0; split <= len(reply); split++ {
			t.Run(fmt.Sprintf("%q/%d", reply, split), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sink := &syncSink{}
					review, pw, program, stop := approvalTestRun(t, sink)
					defer stop()
					review.updates <- approvalTestState("first")
					synctest.Wait()
					_, _ = pw.Write([]byte("program\r~a" + reply[:split]))
					synctest.Wait()
					_, _ = pw.Write([]byte(reply[split:]))
					synctest.Wait()
					require.Equal(t, "program\r"+reply, program.String())
					require.Empty(t, review.answers)
				})
			})
		}
	}
}
