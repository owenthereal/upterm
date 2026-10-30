package attach

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/owenthereal/upterm/upterm"
)

// ApprovalReview delivers the latest primary-local snapshot and sends an answer
// separately from the hosted program's input.
type ApprovalReview interface {
	Updates() <-chan upterm.ApprovalState
	Answer(context.Context, upterm.ApprovalAnswer) error
}

type approvalControl struct {
	updates chan upterm.ApprovalState
	send    func(string, bool, []byte) (bool, []byte, error)
	busy    atomic.Bool
}

func newApprovalControl(send func(string, bool, []byte) (bool, []byte, error)) *approvalControl {
	return &approvalControl{updates: make(chan upterm.ApprovalState, 1), send: send}
}
func (a *approvalControl) Updates() <-chan upterm.ApprovalState { return a.updates }

// The sole global-request reader replaces a queued snapshot, never waits for
// terminal display. An ACK means queued, not displayed or approved.
func (a *approvalControl) accept(payload []byte) bool {
	state, err := upterm.DecodeApprovalState(payload)
	if err != nil {
		return false
	}
	select {
	case <-a.updates:
	default:
	}
	a.updates <- state
	return true
}
func (a *approvalControl) Answer(ctx context.Context, answer upterm.ApprovalAnswer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !a.busy.CompareAndSwap(false, true) {
		return errors.New("approval answer still in flight")
	}
	payload, err := json.Marshal(answer)
	if err != nil {
		a.busy.Store(false)
		return err
	}
	done := make(chan error, 1)
	go func() {
		defer a.busy.Store(false)
		ok, _, err := a.send(upterm.ApprovalAnswerRequest, true, payload)
		if err == nil && !ok {
			err = errors.New("approval answer refused")
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

type approvalRead struct {
	p     []byte
	err   error
	epoch uint64
}
type approvalDisplay struct {
	id         string
	generation uint64
	result     localOutcome
}

// terminalReview is owned by forwardInput's event loop. Only epoch crosses
// into the sole stdin reader, to reject bytes already queued at a boundary.
type terminalReview struct {
	terminal                  *Terminal
	output                    *output
	limits                    terminalLimits
	logger                    *slog.Logger
	updates                   <-chan upterm.ApprovalState
	state                     upterm.ApprovalState
	active, armed             bool
	code, previousCode, typed string
	generation                uint64
	epoch                     atomic.Uint64
	parser                    approvalInput
	programFrame              bool // the current frame prefix has already been forwarded raw
	display                   chan approvalDisplay
	displaying                bool
	dirty                     bool
	lastDisplay               time.Time
	tick                      *time.Ticker
	escapeTimer               *time.Timer
	escapeC                   <-chan time.Time
	answers                   chan error
	answering                 bool
	ctx                       context.Context
	readNext                  chan struct{}
	reading                   bool
}

func newTerminalReview(t *Terminal, o *output, lim terminalLimits, logger *slog.Logger) *terminalReview {
	r := &terminalReview{terminal: t, output: o, limits: lim, logger: logger, display: make(chan approvalDisplay, 1), answers: make(chan error, 1), tick: time.NewTicker(time.Second)}
	if t.Approvals != nil && o.modes != nil && t.Escape != 0 {
		r.updates = t.Approvals.Updates()
	}
	return r
}
func (r *terminalReview) close() {
	r.tick.Stop()
	if r.escapeTimer != nil {
		r.escapeTimer.Stop()
	}
}
func (r *terminalReview) readInput(ctx context.Context, reader io.Reader) <-chan approvalRead {
	reads := make(chan approvalRead, 1)
	r.readNext = make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-r.readNext:
			case <-ctx.Done():
				return
			}
			if ctx.Err() != nil {
				return
			}
			p := make([]byte, 4096)
			n, err := reader.Read(p)
			chunk := approvalRead{p: p[:n], err: err, epoch: r.epoch.Load()}
			select {
			case reads <- chunk:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()
	return reads
}
func (r *terminalReview) invalidate() { r.armed = false; r.typed = ""; r.generation++; r.epoch.Add(1) }
func (r *terminalReview) leave()      { r.active = false; r.dirty = false; r.invalidate() }
func (r *terminalReview) live() bool {
	return r.state.Current != nil && time.Now().UnixMilli() < r.state.Current.DeadlineUnixMilli
}
func (r *terminalReview) enter() {
	r.invalidate()
	if !r.live() {
		r.active = false
		r.dirty = true
		r.render(true)
		return
	}
	r.active = true
	// 20 random bits, an accidental-input confirmation, not authentication.
	for {
		var raw [3]byte
		if _, err := rand.Read(raw[:]); err != nil {
			r.active = false
			return
		}
		r.code = base32.StdEncoding.EncodeToString(raw[:])[:4]
		if r.code != r.previousCode {
			break
		}
	}
	r.previousCode = r.code
	r.dirty = true
	r.render(true)
}
func (r *terminalReview) update(state upterm.ApprovalState) {
	if state.Revision <= r.state.Revision {
		return
	}
	oldID := ""
	if r.state.Current != nil {
		oldID = r.state.Current.ID
	}
	oldPending := r.state.Pending
	r.state = state
	newID := ""
	if state.Current != nil {
		newID = state.Current.ID
	}
	if r.active {
		if oldID != newID {
			r.enter()
		} else {
			r.dirty = true
		}
	} else if oldID != newID || oldPending != state.Pending {
		r.dirty = true
		r.render(false)
	}
}
func (r *terminalReview) render(immediate bool) {
	if !r.dirty || r.displaying || (!immediate && !r.lastDisplay.IsZero() && time.Since(r.lastDisplay) < time.Second) {
		return
	}
	var lines []string
	id := ""
	if r.active && r.live() {
		id = r.state.Current.ID
		lines = approvalLines(r.state, r.code)
	} else if r.state.Pending > 0 && r.live() {
		lines = []string{fmt.Sprintf("upterm: %d permission request(s) pending; %ca reviews the oldest.", r.state.Pending, r.terminal.Escape)}
	} else if r.state.Pending > 0 {
		lines = []string{"upterm: current permission request expired; waiting for the updated queue."}
	} else {
		lines = []string{"upterm: no pending permission requests."}
	}
	r.dirty = false
	r.displaying = true
	r.lastDisplay = time.Now()
	generation := r.generation
	go func() {
		result := r.output.showLocal(lines, r.limits.statusSafe, r.limits.outputDrain, r.logger)
		r.display <- approvalDisplay{id, generation, result}
	}()
}
func (r *terminalReview) next(ctx context.Context, reads <-chan approvalRead) (approvalRead, bool) {
	r.ctx = ctx
	if ctx.Err() != nil {
		return approvalRead{}, false
	}
	if !r.reading {
		r.readNext <- struct{}{}
		r.reading = true
	}
	for {
		if ctx.Err() != nil {
			return approvalRead{}, false
		}
		// Prefer queued state over keystrokes; a resolved request cannot consume
		// an answer while its replacement is already waiting in the control queue.
		select {
		case state, ok := <-r.updates:
			if !ok {
				r.updates = nil
				r.state.Current = nil
				r.state.Pending = 0
				r.leave()
			} else {
				r.update(state)
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return approvalRead{}, false
		case state, ok := <-r.updates:
			if !ok {
				r.updates = nil
				r.state.Current = nil
				r.state.Pending = 0
				r.leave()
			} else {
				r.update(state)
			}
		case done := <-r.display:
			r.displaying = false
			if done.result == localCompleted && r.active && r.live() && r.state.Current.ID == done.id && r.generation == done.generation {
				if !r.armed {
					r.typed = ""
					r.epoch.Add(1)
					r.armed = true
				}
			}
			if r.dirty {
				r.render(r.active && !r.armed)
			}
		case <-r.answers:
			r.answering = false
		case <-r.tick.C:
			if r.active && !r.live() && (r.armed || r.typed != "") {
				// The broker supplies the next live request. Keep review input local
				// until that snapshot arrives rather than leaking a late confirmation.
				r.invalidate()
			}
			if r.active {
				r.dirty = true
			}
			r.render(false)
		case <-r.escapeC:
			r.escapeC = nil
			r.parser.escapeExpired = true
			r.leave()
			// Keep the ESC classifier: a late sequence body still isn't a key.
		case chunk := <-reads:
			r.reading = false
			return chunk, true
		}
	}
}
func (r *terminalReview) input(chunk approvalRead, filter *EscapeFilter) ([]byte, EscapeAction) {
	if !r.active {
		if !filter.approval {
			return filter.Feed(chunk.p)
		}
		if chunk.epoch != r.epoch.Load() {
			replies, _ := r.parser.feed(chunk.p, chunk.epoch)
			return replies, EscapeNone
		}
		return r.programInput(chunk, filter)
	}
	program, keys := r.parser.feed(chunk.p, chunk.epoch)
	if r.parser.loneEscape() {
		if r.escapeC == nil {
			r.escapeTimer = time.NewTimer(50 * time.Millisecond)
			r.escapeC = r.escapeTimer.C
		}
	} else if r.escapeC != nil {
		r.escapeTimer.Stop()
		r.escapeC = nil
	}
	if r.parser.interrupted {
		r.typed = ""
		keys = nil
	}
	// Local detach/suspend remain available even before a display completes.
	for _, b := range keys {
		if b == 0x1b {
			r.leave()
			return program, EscapeNone
		}
		if r.typed == string(r.terminal.Escape) {
			if b == '.' {
				r.leave()
				return program, EscapeDetach
			}
			if b == 0x1a && r.terminal.Suspend != nil {
				r.leave()
				return program, EscapeSuspend
			}
		}
		if !r.armed || chunk.epoch != r.epoch.Load() || !r.live() {
			r.typed = ""
			if b == r.terminal.Escape {
				r.typed = string(b)
			}
			continue
		}
		switch b {
		case '\r', '\n':
			typed := r.typed
			r.typed = ""
			decision := ""
			if typed == "d "+r.code {
				decision = "deny"
			}
			if typed == "c "+r.code {
				decision = "connection"
			}
			if typed == "g "+r.code && r.state.Current.Fingerprint != "" {
				decision = "guest"
			}
			if decision != "" && !r.answering {
				answer := upterm.ApprovalAnswer{ID: r.state.Current.ID, Decision: decision}
				r.invalidate()
				r.answering = true
				parent := r.ctx
				go func() {
					ctx, cancel := context.WithTimeout(parent, time.Second)
					defer cancel()
					r.answers <- r.terminal.Approvals.Answer(ctx, answer)
				}()
				// Remaining bytes from this same read can never answer another request.
				return program, EscapeNone
			}
		case 0x7f, 8:
			if len(r.typed) > 0 {
				r.typed = r.typed[:len(r.typed)-1]
			}
		default:
			if len(r.typed) < 64 {
				r.typed += string(b)
			} else {
				r.typed = ""
				r.armed = false
			}
		}
	}
	return program, EscapeNone
}

// programInput tracks framing even before review starts. Normal-mode frame
// bytes remain program-owned and pass through unchanged; only unframed keys
// reach the local escape filter. A frame left incomplete by review still
// uses the parser's reply output, since its prefix has not been forwarded.
func (r *terminalReview) programInput(chunk approvalRead, filter *EscapeFilter) (out []byte, action EscapeAction) {
	for i, b := range chunk.p {
		data := chunk.p[i : i+1]
		wasFrame := r.parser.inSequence()
		// Feed every byte exactly once, including ordinary text and frame
		// bodies, so UTF-8/control classification cannot depend on mode.
		replies, keys := r.parser.feed(data, chunk.epoch)
		if wasFrame || r.parser.inSequence() {
			if !wasFrame {
				r.programFrame = true
			}
			if r.programFrame {
				// A held escape belongs before this opaque frame, and cannot combine
				// with a later body byte to form a local shortcut.
				out = append(out, filter.Flush()...)
				out = append(out, b)
				filter.lineStart = b == '\r' || b == '\n'
				r.programFrame = r.parser.inSequence()
				continue
			}
			out = append(out, replies...)
			data = keys
		}
		forwarded, current := filter.Feed(data)
		out = append(out, forwarded...)
		switch current {
		case EscapeApproval:
			r.enter()
			// The rest of this read cannot supply review keys, but its framing
			// and replies survive with the original read's ownership epoch.
			replies, _ := r.parser.feed(chunk.p[i+1:], chunk.epoch)
			out = append(out, replies...)
			return out, EscapeApproval
		case EscapeDetach:
			return out, EscapeDetach
		case EscapeSuspend:
			action = EscapeSuspend
		case EscapeStatus:
			if action == EscapeNone {
				action = EscapeStatus
			}
		}
	}
	return
}

func approvalLines(state upterm.ApprovalState, code string) []string {
	request := state.Current
	identity := strconv.QuoteToASCII(request.Fingerprint)
	if request.Fingerprint == "" {
		identity = "unidentified (no authenticated guest key)"
	}
	remaining := max(0, (request.DeadlineUnixMilli-time.Now().UnixMilli()+999)/1000)
	lines := []string{fmt.Sprintf("upterm: guest %s; operation %s; capability %s", identity, strconv.QuoteToASCII(request.Operation), strconv.QuoteToASCII(request.Capability)), fmt.Sprintf("upterm: %ds remaining; %d pending", remaining, state.Pending)}
	for i, subject := range request.Subjects {
		lines = append(lines, fmt.Sprintf("upterm: subject[%d] = %s", i, strconv.QuoteToASCII(string(subject))))
	}
	if request.Capability == "exec" {
		lines = append(lines, "upterm: execution trust: the guest can supply further input and code.")
	}
	lines = append(lines, "upterm: d "+code+" then Enter: deny this request.", "upterm: c "+code+" then Enter: allow this connection, capability, and complete subject tuple.")
	if request.Fingerprint != "" {
		lines = append(lines, "upterm: g "+code+" then Enter: allow this authenticated guest and capability until this host session ends.")
	} else {
		lines = append(lines, "upterm: guest-wide permission is unavailable for an unidentified guest.")
	}
	lines = append(lines, "upterm: Escape leaves review without answering.")
	// Protocol subject bounds expand to at most 32 KiB when quoted. Keep the
	// entire tuple; never truncate a command while offering to approve it.
	if len(strings.Join(lines, "\n")) > 64*1024 {
		return nil
	}
	return lines
}
