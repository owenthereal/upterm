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

// approvalTestReviewShown is in every review: the deny key's line, which
// carries the confirmation code.
const approvalTestReviewShown = "upterm:   n "

func approvalTestCode(t *testing.T, s string) string {
	t.Helper()
	i := strings.LastIndex(s, approvalTestReviewShown)
	require.GreaterOrEqual(t, i, 0, s)
	return s[i+len(approvalTestReviewShown) : i+len(approvalTestReviewShown)+4]
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

func TestApprovalAnswerFailureLogged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		logs := &syncSink{}
		r := newTerminalReview(&Terminal{}, nil, terminalLimits{}, slog.New(slog.NewTextHandler(logs, nil)))
		defer r.close()
		r.readNext = make(chan struct{}, 1)
		r.answering = true
		r.answers <- fmt.Errorf("approval answer refused")
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.next(ctx, make(chan approvalRead))
		}()
		synctest.Wait()
		require.False(t, r.answering)
		require.Contains(t, logs.String(), "approval answer failed")
		require.Contains(t, logs.String(), "approval answer refused")
		cancel()
		<-done
	})
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
		_, _ = pw.Write([]byte("a " + code + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers, "display write is still in flight")
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("y " + code + "\r"))
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
		_, _ = pw.Write([]byte("a " + code[:2]))
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
		_, _ = pw.Write([]byte("a " + code + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("n " + nextCode + "\r"))
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
		_, _ = pw.Write([]byte("program\r~aa FAKE\r"))
		synctest.Wait()
		require.Equal(t, "program\r", program.String())
		code := approvalTestCode(t, sink.String())
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("\x1b]52;c;a " + code + "\r\a\x1b[200~a " + code + "\r\x1b[201~"))
		synctest.Wait()
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("y " + code + "\r"))
		synctest.Wait()
		require.Len(t, r.answers, 1)
		require.NotContains(t, program.String(), "y "+code)
	})
}

// A full tuple is displayed losslessly, including invalid bytes, literal escape
// text and Unicode controls, and so is a key or label that isn't plain text.
// An unidentified peer is never offered a guest-wide answer.
func TestApprovalVisibleSubjects(t *testing.T) {
	state := approvalTestState("bytes")
	state.Current.Fingerprint = "key\n\x1b\u202e"
	state.Current.Operation = "rename"
	state.Current.Capability = "sftp"
	state.Current.Subjects = [][]byte{{0xff}, []byte("\ufffd\\xff\n\x1b\u202e")}
	lines := strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Contains(t, lines, `wants to rename "\xff" to "\ufffd\\xff\n\x1b\u202e"`)
	require.Contains(t, lines, `upterm: a guest with key "key\n\x1b\u202e" wants to`)
	require.NotContains(t, lines, "\x1b")
	require.NotContains(t, lines, "\u202e")
	state.Current.Guest = "alice\u202e (github:alice)"
	lines = strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Contains(t, lines, `upterm: "alice\u202e (github:alice)" wants to`)
	require.NotContains(t, lines, "\u202e")
	state.Current.Guest = ""
	state.Current.Fingerprint = ""
	lines = strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Contains(t, lines, "unidentified")
	require.NotContains(t, lines, "a ABCD")
	state.Current.Subjects = [][]byte{bytes.Repeat([]byte{0xff}, 4096), bytes.Repeat([]byte{0xfe}, 4096)}
	lines = strings.Join(approvalLines(state, "ABCD"), "\n")
	require.Equal(t, 4096, strings.Count(lines, `\xff`))
	require.Equal(t, 4096, strings.Count(lines, `\xfe`))
}

// The review says who is asking, by the host's own label for its key -- a
// named user, or the key and the file or URL it came from -- or by the key,
// saying when anyone with the session ID can join; what it wants, in the
// words of what it does; and what each answer allows. A file answer is for
// the paths shown, not for the one operation that asked, so it says what else
// it allows.
func TestApprovalReviewSaysWhatItDecides(t *testing.T) {
	keys := func(allowOne, allowGuest string) []string {
		return []string{
			"upterm:   y ABCD Enter   " + allowOne,
			"upterm:   a ABCD Enter   " + allowGuest,
			"upterm:   n ABCD Enter   deny",
			"upterm:   Esc            decide later (it still expires)",
		}
	}
	const shell = "upterm: Allowing it lets this guest send more commands through it, so treat it as giving a shell."
	execKeys := keys("allow this command, on this connection only", "allow this guest to run any command until this session ends")
	pathKeys := keys("allow every file operation on this path, including writes and deletes, on this connection only", "allow this guest every file operation on any path, including writes and deletes, until this session ends")
	pairKeys := keys("allow renaming, linking or symlinking the first path to the second, on this connection only", "allow this guest every file operation on any path, including writes and deletes, until this session ends")
	const readOnly = "upterm: a read-only session still allows downloads only."
	alice := upterm.ApprovalRequest{Fingerprint: "SHA256:3Jx9", Guest: "alice (github:alice)"}
	for _, tc := range []struct {
		name      string
		who       upterm.ApprovalRequest
		operation string
		subjects  []string
		pending   uint32
		want      []string
	}{
		{"exec by a listed guest", alice, "exec", []string{"bash"}, 2, append([]string{
			`upterm: alice (github:alice) wants to run a command on this machine: "bash"`, shell, "upterm: 57s left; 1 more waiting.",
		}, execKeys...)},
		{"exec by a guest an entry names no one for", upterm.ApprovalRequest{
			Fingerprint: "SHA256:NjkIYAtFt4JkGVLZL0P8B0AXyCnb5oKDHh5H9yOF6/o",
			Guest:       "a guest with key SHA256:NjkIYAtFt4JkGVLZL0P8B0AXyCnb5oKDHh5H9yOF6/o from /home/owen/.ssh/authorized_keys",
		}, "exec", []string{"bash"}, 1, append([]string{
			`upterm: a guest with key SHA256:NjkIYAtFt4JkGVLZL0P8B0AXyCnb5oKDHh5H9yOF6/o from /home/owen/.ssh/authorized_keys wants to run a command on this machine: "bash"`, shell, "upterm: 57s left; 0 more waiting.",
		}, execKeys...)},
		{"exec on an open session", upterm.ApprovalRequest{Fingerprint: "SHA256:3Jx9", Unlisted: true}, "exec", []string{"make test"}, 1, append([]string{
			`upterm: a guest with key SHA256:3Jx9 (anyone with the session ID can join) wants to run a command on this machine: "make test"`, shell, "upterm: 57s left; 0 more waiting.",
		}, execKeys...)},
		{"exec by a key with no label", upterm.ApprovalRequest{Fingerprint: "SHA256:3Jx9"}, "exec", []string{"bash"}, 1, append([]string{
			`upterm: a guest with key SHA256:3Jx9 wants to run a command on this machine: "bash"`, shell, "upterm: 57s left; 0 more waiting.",
		}, execKeys...)},
		{"exec by an unidentified guest", upterm.ApprovalRequest{}, "exec", []string{"bash"}, 1, []string{
			`upterm: an unidentified guest (no authenticated key) wants to run a command on this machine: "bash"`, shell, "upterm: 57s left; 0 more waiting.",
			"upterm:   y ABCD Enter   allow this command, on this connection only",
			"upterm:   n ABCD Enter   deny",
			"upterm:   Esc            decide later (it still expires)",
			"upterm: an unidentified guest can't be allowed beyond this connection.",
		}},
		{"forward", alice, "forward", []string{"127.0.0.1", "5432"}, 1, append([]string{
			"upterm: alice (github:alice) wants to reach 127.0.0.1:5432 on this machine", "upterm: 57s left; 0 more waiting.",
		}, keys("allow this destination, on this connection only", "allow this guest to reach any loopback port on this machine until this session ends")...)},
		{"forward to IPv6", alice, "forward", []string{"::1", "22"}, 1, append([]string{
			"upterm: alice (github:alice) wants to reach [::1]:22 on this machine", "upterm: 57s left; 0 more waiting.",
		}, keys("allow this destination, on this connection only", "allow this guest to reach any loopback port on this machine until this session ends")...)},
		{"upload", alice, "upload", []string{"/home/alice/notes.txt"}, 1, append(append([]string{
			`upterm: alice (github:alice) wants to write "/home/alice/notes.txt"`, "upterm: 57s left; 0 more waiting.",
		}, pathKeys...), readOnly)},
		{"download", alice, "download", []string{"/notes.txt"}, 1, append(append([]string{
			`upterm: alice (github:alice) wants to read "/notes.txt"`, "upterm: 57s left; 0 more waiting.",
		}, pathKeys...), readOnly)},
		{"delete", alice, "delete", []string{"/notes.txt"}, 1, append(append([]string{`upterm: alice (github:alice) wants to delete "/notes.txt"`, "upterm: 57s left; 0 more waiting."}, pathKeys...), readOnly)},
		{"mkdir", alice, "mkdir", []string{"/d"}, 1, append(append([]string{`upterm: alice (github:alice) wants to create the directory "/d"`, "upterm: 57s left; 0 more waiting."}, pathKeys...), readOnly)},
		{"rmdir", alice, "rmdir", []string{"/d"}, 1, append(append([]string{`upterm: alice (github:alice) wants to remove the directory "/d"`, "upterm: 57s left; 0 more waiting."}, pathKeys...), readOnly)},
		{"setstat", alice, "setstat", []string{"/d"}, 1, append(append([]string{`upterm: alice (github:alice) wants to change the attributes of "/d"`, "upterm: 57s left; 0 more waiting."}, pathKeys...), readOnly)},
		{"rename", alice, "rename", []string{"/a", "/b"}, 1, append(append([]string{`upterm: alice (github:alice) wants to rename "/a" to "/b"`, "upterm: 57s left; 0 more waiting."}, pairKeys...), readOnly)},
		{"symlink", alice, "symlink", []string{"/a", "/b"}, 1, append(append([]string{`upterm: alice (github:alice) wants to make "/a" a symlink to "/b"`, "upterm: 57s left; 0 more waiting."}, pairKeys...), readOnly)},
		{"link", alice, "link", []string{"/a", "/b"}, 1, append(append([]string{`upterm: alice (github:alice) wants to make "/a" a hard link to "/b"`, "upterm: 57s left; 0 more waiting."}, pairKeys...), readOnly)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				request := tc.who
				request.ID, request.Operation, request.DeadlineUnixMilli = "review", tc.operation, time.Now().Add(57*time.Second).UnixMilli()
				request.Capability = map[string]string{"exec": "exec", "forward": "forward"}[tc.operation]
				if request.Capability == "" {
					request.Capability = "sftp"
				}
				for _, subject := range tc.subjects {
					request.Subjects = append(request.Subjects, []byte(subject))
				}
				require.Equal(t, tc.want, approvalLines(upterm.ApprovalState{Revision: 1, Pending: tc.pending, Current: &request}, "ABCD"))
			})
		})
	}
}

// Only the review's own keys answer it, with the code it shows: the letters
// an earlier review used, a guest-wide answer for a guest with no key, a wrong
// code and a bare letter all change nothing, and the program is sent none of
// them.
func TestApprovalAnswersOnlyItsOwnKeys(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		r, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		state := approvalTestState("first")
		state.Current.Fingerprint = ""
		r.updates <- state
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		code := approvalTestCode(t, sink.String())
		for _, typed := range []string{"c " + code, "g " + code, "d " + code, "a " + code, "y ZZZZ", "y", "yes"} {
			_, _ = pw.Write([]byte(typed + "\r"))
			synctest.Wait()
		}
		require.Empty(t, r.answers)
		_, _ = pw.Write([]byte("y " + code + "\r"))
		synctest.Wait()
		require.Equal(t, upterm.ApprovalAnswer{ID: "first", Decision: "connection"}, <-r.answers)
		require.Empty(t, program.String())
	})
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
					require.NotContains(t, sink.String(), approvalTestReviewShown)
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
				confirmation := "a " + approvalTestCode(t, sink.String()) + "\r"
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
		_, _ = pw.Write([]byte("]52;c;a " + old + "\r~a"))
		synctest.Wait()
		require.Empty(t, r.answers)
		require.NotContains(t, sink.String()[strings.LastIndex(sink.String(), approvalTestReviewShown):], "new request")
		_, _ = pw.Write([]byte("\a~a"))
		synctest.Wait()
		code := approvalTestCode(t, sink.String())
		require.NotEqual(t, old, code)
		require.Contains(t, program.String(), "\x1b]52;c;a "+old+"\r~a\a")
		_, _ = pw.Write([]byte("y " + code + "\r"))
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
				_, _ = pw.Write([]byte("a " + code[:2]))
				synctest.Wait()
				switch end {
				case "expiry":
					time.Sleep(61 * time.Second)
				case "guest-wide":
					r.updates <- upterm.ApprovalState{Revision: 2}
				default:
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
		defer func() { _ = pw.Close() }()
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
		_, _ = pw.Write([]byte("y " + code + "\r"))
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
				_, _ = pw.Write([]byte("a " + code + "\r"))
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
	n, err := s.syncSink.Write(p)
	if err != nil {
		return n, err
	}
	if s.short {
		return n - 1, nil
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
					_, _ = pw.Write([]byte(framing.start[split:] + "a " + code + "\r" + framing.end))
					synctest.Wait()
					require.Empty(t, r.answers)
					_, _ = pw.Write([]byte("y " + code + "\r"))
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
		_, _ = pw.Write([]byte("\ra " + code + "\r\a"))
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
		_, _ = pw.Write([]byte("y " + first + "\ry " + code + "\r"))
		synctest.Wait()
		require.Empty(t, review.answers, "the first completion must not arm the still-undisplayed replacement")
		sink.release <- struct{}{}
		synctest.Wait()
		_, _ = pw.Write([]byte("y " + code + "\r"))
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
	inputEnded := make(chan struct{})
	door := serveDoor(t, func(s gssh.Session) {
		_, wins, _ := s.Pty()
		go func() {
			for range wins {
			}
		}()
		_, _ = io.WriteString(s, "READY")
		_, _ = io.Copy(program, s) // returns when the client's input ends
		close(inputEnded)
	})
	review := &approvalTestReview{make(chan upterm.ApprovalState, 8), make(chan upterm.ApprovalAnswer, 8)}
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()
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
	waitFor(t, func() bool { return strings.Contains(sink.String(), approvalTestReviewShown) }, "review")
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
	waitFor(t, func() bool { return strings.Count(sink.String(), approvalTestReviewShown) >= 2 }, "re-entry")
	code := approvalTestCode(t, sink.String())
	require.NotEqual(t, oldCode, code)
	_, err = pw.Write([]byte("a " + oldCode + "\r!."))
	require.NoError(t, err)
	res := awaitResult(t, done)
	require.Equal(t, Detached, res.Reason)
	require.Empty(t, review.answers)
	// The detach waits for what was typed to be sent, not for the door to
	// have read it: the door reads on its own goroutine, on the far side of
	// the connection, and may not have got to it yet. So the door's input is
	// read to its end before it is looked at.
	awaitClosed(t, inputEnded, "the door's input never ended")
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
		_, _ = pw.Write([]byte("a " + old + "\r"))
		synctest.Wait()
		require.Empty(t, r.answers)
		require.NotContains(t, program.String(), "a "+old)
		next := approvalTestState("next")
		next.Revision = 2
		r.updates <- next
		synctest.Wait()
		require.Contains(t, sink.String(), approvalTestReviewShown)
		code := approvalTestCode(t, sink.String())
		require.NotEqual(t, old, code)
		_, _ = pw.Write([]byte("y " + code + "\r"))
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
		before := strings.Count(sink.String(), approvalTestReviewShown)
		close(r.updates)
		synctest.Wait()
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		require.Equal(t, before, strings.Count(sink.String(), approvalTestReviewShown))
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
		_, _ = r.input(approvalRead{p: []byte("a ABCD\r"), epoch: 1}, filter)
		synctest.Wait()
		require.Empty(t, review.answers, "queued before display completion")
		_, _ = r.input(approvalRead{p: []byte("y ABCD\r"), epoch: 2}, filter)
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
				confirmation := "a " + approvalTestCode(t, sink.String()) + "\r"
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
				_, _ = pw.Write([]byte("y " + code + "\r"))
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

func TestApprovalNormalFramesKeepProgramOwnership(t *testing.T) {
	frames := []struct{ name, start, end string }{
		{"paste", "\x1b[200~", "\x1b[201~"},
		{"OSC", "\x1b]52;c;", "\a"},
		{"DCS", "\x1bP1$r", "\x1b\\"},
		{"APC", "\x1b_", "\x1b\\"},
		{"C1-paste", "\x9b200~", "\x9b201~"},
		{"C1-OSC", "\x9d52;c;", "\x9c"},
		{"C1-DCS", "\x901$r", "\x9c"},
		{"C1-APC", "\x9f", "\x9c"},
	}
	for _, frame := range frames {
		prefix := frame.start + "\r~a"
		for split := 0; split <= len(prefix); split++ {
			t.Run(fmt.Sprintf("%s/%d", frame.name, split), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sink := &syncSink{}
					review, pw, program, stop := approvalTestRun(t, sink)
					defer stop()
					review.updates <- approvalTestState("first")
					synctest.Wait()
					_, _ = pw.Write([]byte(prefix[:split]))
					synctest.Wait()
					_, _ = pw.Write([]byte(prefix[split:]))
					synctest.Wait()
					// If the shortcut was incorrectly recognized, use the displayed code
					// to prove that subsequent marked-body input still cannot answer it.
					code := "ABCD"
					if strings.Contains(sink.String(), approvalTestReviewShown) {
						code = approvalTestCode(t, sink.String())
					}
					continuation := "a " + code + "\r"
					_, _ = pw.Write([]byte(continuation[:3]))
					synctest.Wait()
					_, _ = pw.Write([]byte(continuation[3:]))
					synctest.Wait()
					require.Empty(t, review.answers, "a known normal-mode frame must not approve")
					require.NotContains(t, sink.String(), approvalTestReviewShown, "a shortcut inside a frame must not capture the keyboard")
					for _, b := range []byte(frame.end) {
						_, _ = pw.Write([]byte{b})
						synctest.Wait()
					}
					_, _ = pw.Write([]byte("\r"))
					synctest.Wait()
					expected := prefix + continuation + frame.end + "\r"
					require.Equal(t, expected, program.String(), "framing and payload remain program-owned, exactly once")
					_, _ = pw.Write([]byte("~a"))
					synctest.Wait()
					fresh := approvalTestCode(t, sink.String())
					_, _ = pw.Write([]byte("y " + fresh + "\r"))
					synctest.Wait()
					require.Len(t, review.answers, 1)
					require.Equal(t, upterm.ApprovalAnswer{ID: "first", Decision: "connection"}, <-review.answers)
					require.Equal(t, expected, program.String())
				})
			})
		}
	}
}

func TestApprovalPendingEscapeBeforeFrame(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(fmt.Sprint(fragmented), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sink := &syncSink{}
				review, pw, program, stop := approvalTestRun(t, sink)
				defer stop()
				review.updates <- approvalTestState("first")
				synctest.Wait()
				input := "~\x1b[200~\r~a\r~~a\x1b[201~tail\r"
				if fragmented {
					for _, b := range []byte(input) {
						_, _ = pw.Write([]byte{b})
						synctest.Wait()
					}
				} else {
					_, _ = pw.Write([]byte(input))
					synctest.Wait()
				}
				require.Equal(t, input, program.String(), "the held escape and framed body must stay byte-exact")
				require.NotContains(t, sink.String(), approvalTestReviewShown)
				require.Empty(t, review.answers)
				_, _ = pw.Write([]byte("~a"))
				synctest.Wait()
				code := approvalTestCode(t, sink.String())
				_, _ = pw.Write([]byte("y " + code + "\r"))
				synctest.Wait()
				require.Len(t, review.answers, 1)
			})
		})
	}
}

func TestApprovalOrdinarySplitInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sink := &syncSink{}
		review, pw, program, stop := approvalTestRun(t, sink)
		defer stop()
		review.updates <- approvalTestState("first")
		synctest.Wait()
		// These UTF-8 characters contain bytes that are standalone C1 introducers.
		// They remain ordinary program text even when each byte arrives separately.
		input := "ordinary ~text \u2010\u201b\u201d\u201f\r"
		for _, b := range []byte(input) {
			_, _ = pw.Write([]byte{b})
			synctest.Wait()
		}
		require.Equal(t, input, program.String())
		require.NotContains(t, sink.String(), approvalTestReviewShown)
		_, _ = pw.Write([]byte("~a"))
		synctest.Wait()
		require.Contains(t, sink.String(), approvalTestReviewShown, "ordinary split UTF-8 must not leave a false control frame open")
		code := approvalTestCode(t, sink.String())
		_, _ = pw.Write([]byte("y " + code + "\r"))
		synctest.Wait()
		require.Len(t, review.answers, 1)
		require.Equal(t, input, program.String())
	})
}

func approvalUTF8FrameCases() []struct{ name, start, end, imitation string } {
	return []struct{ name, start, end, imitation string }{
		{"paste", "\x1b[200~", "\x1b[201~", "\u201b201~"},
		{"OSC", "\x1b]0;", "\a", "\u201c"},
		{"DCS", "\x1bP", "\x1b\\", "\u201c"},
		{"APC", "\x1b_", "\x1b\\", "\u201c"},
		{"C1-paste", "\x9b200~", "\x9b201~", "\u201b201~"},
		{"C1-OSC", "\x9d0;", "\x9c", "\u201c"},
		{"C1-DCS", "\x90", "\x9c", "\u201c"},
		{"C1-APC", "\x9f", "\x9c", "\u201c"},
	}
}

func TestApprovalUTF8InsideNormalFrames(t *testing.T) {
	for _, frame := range approvalUTF8FrameCases() {
		prefix := frame.start + frame.imitation + "\r~a"
		for split := -1; split <= len(prefix); split++ {
			t.Run(fmt.Sprintf("%s/%d", frame.name, split), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sink := &syncSink{}
					review, pw, program, stop := approvalTestRun(t, sink)
					defer stop()
					review.updates <- approvalTestState("first")
					synctest.Wait()
					chunks := []string{}
					if split < 0 {
						for _, b := range []byte(prefix) {
							chunks = append(chunks, string([]byte{b}))
						}
					} else {
						chunks = []string{prefix[:split], prefix[split:]}
					}
					for _, chunk := range chunks {
						_, _ = pw.Write([]byte(chunk))
						synctest.Wait()
					}
					code := "ABCD"
					if strings.Contains(sink.String(), approvalTestReviewShown) {
						code = approvalTestCode(t, sink.String())
					}
					continuation := "a " + code + "\r"
					_, _ = pw.Write([]byte(continuation))
					synctest.Wait()
					require.Empty(t, review.answers, "a UTF-8 continuation cannot terminate the known frame")
					require.NotContains(t, sink.String(), approvalTestReviewShown, "the true terminator has not arrived")
					require.Equal(t, prefix+continuation, program.String())
					for _, b := range []byte(frame.end) {
						_, _ = pw.Write([]byte{b})
						synctest.Wait()
					}
					_, _ = pw.Write([]byte("\r~a"))
					synctest.Wait()
					fresh := approvalTestCode(t, sink.String())
					_, _ = pw.Write([]byte("y " + fresh + "\r"))
					synctest.Wait()
					require.Len(t, review.answers, 1)
					require.Equal(t, upterm.ApprovalAnswer{ID: "first", Decision: "connection"}, <-review.answers)
					require.Equal(t, prefix+continuation+frame.end+"\r", program.String())
				})
			})
		}
	}
}

func TestApprovalUTF8InsideReviewFrames(t *testing.T) {
	for _, frame := range approvalUTF8FrameCases() {
		for _, fragmented := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", frame.name, fragmented), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					sink := &syncSink{}
					review, pw, program, stop := approvalTestRun(t, sink)
					defer stop()
					review.updates <- approvalTestState("first")
					synctest.Wait()
					_, _ = pw.Write([]byte("~a"))
					synctest.Wait()
					code := approvalTestCode(t, sink.String())
					prefix := frame.start + frame.imitation
					if fragmented {
						for _, b := range []byte(prefix) {
							_, _ = pw.Write([]byte{b})
							synctest.Wait()
						}
					} else {
						_, _ = pw.Write([]byte(prefix))
						synctest.Wait()
					}
					continuation := "\ra " + code + "\r"
					_, _ = pw.Write([]byte(continuation))
					synctest.Wait()
					require.Empty(t, review.answers, "review uses the same UTF-8 body classifier")
					require.Empty(t, program.String(), "a string reply is incomplete until the genuine terminator")
					for _, b := range []byte(frame.end) {
						_, _ = pw.Write([]byte{b})
						synctest.Wait()
					}
					if strings.Contains(frame.name, "paste") {
						require.Empty(t, program.String())
					} else {
						require.Equal(t, prefix+continuation+frame.end, program.String())
					}
					_, _ = pw.Write([]byte("y " + code + "\r"))
					synctest.Wait()
					require.Len(t, review.answers, 1)
				})
			})
		}
	}
}
