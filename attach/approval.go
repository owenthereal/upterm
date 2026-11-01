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
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

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
		case err := <-r.answers:
			r.answering = false
			if err != nil {
				r.logger.Warn("approval answer failed", "error", err)
			}
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
			if typed == "n "+r.code {
				decision = "deny"
			}
			if typed == "y "+r.code {
				decision = "connection"
			}
			if typed == "a "+r.code && r.state.Current.Fingerprint != "" {
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

// approvalLines is the review of state's current request: who asks, what it
// wants, how long is left, and what each answer allows. Every subject is
// shown whole and quoted, so a command or path hides nothing in it.
func approvalLines(state upterm.ApprovalState, code string) []string {
	request := state.Current
	who := approvalAsker(*request)
	var lines []string
	var allowOne, allowGuest string
	switch request.Capability {
	case "exec":
		lines = append(lines, "upterm: "+who+" wants to run a command on this machine: "+strconv.QuoteToASCII(string(request.Subjects[0])),
			"upterm: Allowing it lets this guest send more commands through it, so treat it as giving a shell.")
		allowOne = "allow this command, on this connection only"
		allowGuest = "allow this guest to run any command until this session ends"
	case "forward":
		lines = append(lines, "upterm: "+who+" wants to reach "+reviewText(net.JoinHostPort(string(request.Subjects[0]), string(request.Subjects[1])))+" on this machine")
		allowOne = "allow this destination, on this connection only"
		allowGuest = "allow this guest to reach any loopback port on this machine until this session ends"
	default:
		lines = append(lines, "upterm: "+who+" wants to "+fileRequest(request.Operation, request.Subjects))
		// A file grant is for the paths shown, not the operation that asked:
		// a download's approval also lets this connection overwrite or delete.
		allowOne = "allow every file operation on this path, including writes and deletes, on this connection only"
		if len(request.Subjects) == 2 {
			allowOne = "allow renaming, linking or symlinking the first path to the second, on this connection only"
		}
		allowGuest = "allow this guest every file operation on any path, including writes and deletes, until this session ends"
	}
	remaining := max(0, (request.DeadlineUnixMilli-time.Now().UnixMilli()+999)/1000)
	lines = append(lines, fmt.Sprintf("upterm: %ds left; %d more waiting.", remaining, max(state.Pending, 1)-1),
		"upterm:   y "+code+" Enter   "+allowOne)
	if request.Fingerprint != "" {
		lines = append(lines, "upterm:   a "+code+" Enter   "+allowGuest)
	}
	lines = append(lines, "upterm:   n "+code+" Enter   deny", "upterm:   Esc            decide later (it still expires)")
	if request.Fingerprint == "" {
		lines = append(lines, "upterm: an unidentified guest can't be allowed beyond this connection.")
	}
	if request.Capability == "sftp" {
		lines = append(lines, "upterm: a read-only session still allows downloads only.")
	}
	// Protocol subject bounds expand to at most 32 KiB when quoted. Keep the
	// entire tuple; never truncate a command while offering to approve it.
	if len(strings.Join(lines, "\n")) > 64*1024 {
		return nil
	}
	return lines
}

// approvalAsker names who is asking: by the host's own label for its key when
// the key is on the allowlist, else by the key, saying so when the session has
// no allowlist and anyone with its ID can join.
func approvalAsker(request upterm.ApprovalRequest) string {
	switch {
	case request.Fingerprint == "":
		return "an unidentified guest (no authenticated key)"
	case request.Guest != "":
		return reviewText(request.Guest)
	case request.Unlisted:
		return "a guest with key " + reviewText(request.Fingerprint) + " (anyone with the session ID can join)"
	}
	return "a guest with key " + reviewText(request.Fingerprint)
}

// fileRequest is what a file operation wants, in the words of what it does to
// the paths shown. A link is made at the first path, to the second.
func fileRequest(operation string, subjects [][]byte) string {
	path := strconv.QuoteToASCII(string(subjects[0]))
	switch operation {
	case "download":
		return "read " + path
	case "upload":
		return "write " + path
	case "delete":
		return "delete " + path
	case "mkdir":
		return "create the directory " + path
	case "rmdir":
		return "remove the directory " + path
	case "setstat":
		return "change the attributes of " + path
	case "rename":
		return "rename " + path + " to " + strconv.QuoteToASCII(string(subjects[1]))
	case "symlink":
		return "make " + path + " a symlink to " + strconv.QuoteToASCII(string(subjects[1]))
	case "link":
		return "make " + path + " a hard link to " + strconv.QuoteToASCII(string(subjects[1]))
	}
	return "change " + path
}

// reviewText is text the review shows that isn't a subject: as it is when it
// is all printable, quoted otherwise, so that nothing in it acts on the
// terminal or reorders what follows.
func reviewText(s string) string {
	if !utf8.ValidString(s) {
		return strconv.QuoteToASCII(s)
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}
