package join

import (
	"bytes"
	"io"
	"sync"

	"github.com/owenthereal/upterm/attach"
)

// waitKey is a key the guest pressed while join, and not a session, had the
// keyboard.
type waitKey int

const (
	// keyRetry is Enter: attempt now instead of waiting.
	keyRetry waitKey = iota + 1
	// keyStop is Ctrl-C: stop, as the signal would have before the terminal
	// was taken.
	keyStop
	// keyLeave is the escape sequence, or the terminal going away: leave.
	keyLeave
)

// input is the one reader of the guest's keys once join has taken the
// terminal. Each chunk it reads goes to exactly one place: the session whose
// view is active, or join itself. A session is handed nothing until its view
// is activated, which happens only once it is ready and the guest has been
// told so. At every other time, waiting, attempting, setting up, the keys are
// join's: Enter attempts at once, Ctrl-C stops, the escape sequence leaves,
// and everything else is dropped. So nothing typed while join had the
// keyboard ever reaches a session, and a Ctrl-C before a session is ready
// stops join instead of going to a shell that isn't reading yet.
type input struct {
	r      io.Reader
	escape byte
	keyc   chan waitKey
	once   sync.Once

	// handing, when non-nil (tests only), receives once each time the reader
	// starts handing a chunk to a view, before the hand-off completes. It is
	// set before start.
	handing chan struct{}

	mu sync.Mutex
	// current is the active view; nil while the keys are join's.
	current *view
	// last is the most recent view, which a new session supersedes.
	last *view
	// controls is the stretch of time the keys are join's; while a view is
	// active, the one its activation ended.
	controls *controls
	// err is r's terminal error. It is set once, just before ended closes.
	err   error
	ended chan struct{}
}

// controls is one stretch of time in which the keys are join's: from start,
// or from the close of the view that had them, until a view is activated.
// Each begins at the start of a line with nothing pending, so that nothing
// typed before a session, half an escape sequence say, combines with what is
// typed after it.
type controls struct {
	// over closes when a view is activated. A key join hasn't taken by then
	// is dropped, with the rest of its chunk: join has moved on, and those
	// keys were never the session's.
	over chan struct{}

	// The reader's alone.
	filter *attach.EscapeFilter
	// cr says the last byte was '\r', so that a '\n' straight after it, as a
	// terminal that sends Enter as CRLF does, is the same Enter and not a
	// second one.
	cr bool
}

func newControls(escape byte) *controls {
	return &controls{over: make(chan struct{}), filter: attach.NewEscapeFilter(escape, false)}
}

// newInput returns the reader of r. escape is the escape byte that, at the
// start of a line and followed by '.', leaves; zero disables it.
func newInput(r io.Reader, escape byte) *input {
	return &input{
		r:        r,
		escape:   escape,
		keyc:     make(chan waitKey),
		controls: newControls(escape),
		ended:    make(chan struct{}),
	}
}

// start begins the one reader goroutine. It is called once, when join takes
// the terminal: before then stdin belongs to the prompts. A second call does
// nothing, so that r never has two readers.
func (in *input) start() {
	in.once.Do(func() { go in.read() })
}

// session creates a view for one session. It starts inactive: chunks keep
// going to join's keys until it is activated, so that a session still being
// set up, or whose Joined line is still being written, is handed nothing. A
// view the caller hasn't closed is closed here: a new session supersedes the
// last one, and two open views would leave it unclear whose the keys are.
func (in *input) session() *view {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.last != nil {
		in.last.closeLocked()
	}
	v := &view{
		in:     in,
		chunks: make(chan []byte),
		done:   make(chan struct{}),
		took:   make(chan struct{}),
	}
	in.last = v
	return v
}

// keys delivers join's keys whenever no view is active: during waits,
// attempts, setup and the Joined line. A key is delivered only while that
// lasts. One not taken before a view is activated is dropped, so that a key
// pressed before a session never acts on a wait after it.
func (in *input) keys() <-chan waitKey {
	return in.keyc
}

// read is the reader goroutine: the only caller of r.Read.
func (in *input) read() {
	buf := make([]byte, 4096)
	for {
		n, err := in.r.Read(buf)
		if n > 0 {
			in.route(buf[:n])
		}
		if err != nil {
			in.end(err)
			return
		}
	}
}

// route gives chunk to whoever has the keyboard as it is handed over: the
// active view, or join.
func (in *input) route(chunk []byte) {
	in.mu.Lock()
	v, c := in.current, in.controls
	in.mu.Unlock()
	if v != nil {
		// A copy: the view keeps what a short Read leaves, and buf is read
		// into again as soon as the hand-off completes.
		in.hand(v, bytes.Clone(chunk))
		return
	}
	in.control(c, chunk)
}

// hand gives chunk to v, or drops it if v closes first. It never goes
// anywhere else: it was typed at a session, and the session is gone. Above
// all it is not join's, whose Enter would attempt again.
func (in *input) hand(v *view, chunk []byte) {
	if in.handing != nil {
		in.handing <- struct{}{}
	}
	select {
	case v.chunks <- chunk:
	case <-v.done:
	}
}

// control reads join's keys from chunk.
func (in *input) control(c *controls, chunk []byte) {
	out, action := c.filter.Feed(chunk)
	if action == attach.EscapeDetach {
		in.send(c, keyLeave)
		return
	}
	for _, b := range out {
		var k waitKey
		switch {
		case b == 0x03:
			k = keyStop
		case b == '\r', b == '\n' && !c.cr:
			k = keyRetry
		}
		c.cr = b == '\r'
		if k != 0 && !in.send(c, k) {
			return
		}
	}
}

// send delivers k to join, unless a view is activated first. It reports
// whether k was delivered.
func (in *input) send(c *controls, k waitKey) bool {
	select {
	case in.keyc <- k:
		return true
	case <-c.over:
		return false
	}
}

// end delivers r's terminal error, EOF or another: the terminal went away.
// If a view is active, its Read returns it and the session ends as the guest
// leaving; with no view active, or one that closes without taking it, join
// gets keyLeave instead. It also sticks: every Read from then on returns it
// at once, active or not, so that no later session waits for input that is
// gone.
func (in *input) end(err error) {
	in.mu.Lock()
	in.err = err
	close(in.ended)
	for {
		v, c := in.current, in.controls
		in.mu.Unlock()
		if v != nil {
			select {
			case <-v.took:
				return
			case <-v.done:
			}
			// Taken, and then closed, before this looked.
			select {
			case <-v.took:
				return
			default:
			}
		} else if in.send(c, keyLeave) {
			return
		}
		// v closed without taking it, or a view was activated before join
		// took its keyLeave: see who has the keyboard now.
		in.mu.Lock()
	}
}

// view is one session's share of the input: its Terminal's Stdin.
type view struct {
	in *input
	// chunks is where the reader hands a chunk over. Unbuffered, so that a
	// chunk is either this view's or, if it closes first, nobody's.
	chunks chan []byte
	// done closes with Close; closed is under in.mu.
	done   chan struct{}
	closed bool
	// took closes when Read returns r's terminal error.
	took     chan struct{}
	tookOnce sync.Once
	// rest is what a short Read left of the last chunk. Read's alone.
	rest []byte
}

// activate routes every later chunk to v, until v is closed. It is called
// once the session is ready and the guest has been told so, never before: a
// Ctrl-C until then is join's. Activating a closed view does nothing.
func (v *view) activate() {
	in := v.in
	in.mu.Lock()
	defer in.mu.Unlock()
	if v.closed || in.current == v {
		return
	}
	// Only the last view can be open, so nothing else is active: the keys
	// are join's, and stop being so now.
	in.current = v
	close(in.controls.over)
}

// Read blocks until an active v has a chunk, or v is closed (io.EOF). A p
// shorter than the chunk leaves the rest for the next Read. Once r has
// ended, Read returns its error, active or not, as soon as what v was handed
// is delivered.
//
// Terminal reads Stdin through a goroutine that can outlive its Read, so a
// Read in progress returns when v closes: a closed view would otherwise leave
// that goroutine parked for good.
func (v *view) Read(p []byte) (int, error) {
	if len(v.rest) == 0 {
		select {
		case v.rest = <-v.chunks:
		case <-v.done:
		case <-v.in.ended:
			if !v.isClosed() {
				v.tookOnce.Do(func() { close(v.took) })
				return 0, v.in.err
			}
		}
	}
	if v.isClosed() {
		v.rest = nil
		return 0, io.EOF
	}
	n := copy(p, v.rest)
	v.rest = v.rest[n:]
	return n, nil
}

// Close drops what v hasn't delivered and returns the keys to join, at the
// start of a line. It is called once the session has returned, so nothing
// still reads v but a goroutine whose read has been abandoned. Closing twice
// does nothing.
func (v *view) Close() error {
	v.in.mu.Lock()
	defer v.in.mu.Unlock()
	v.closeLocked()
	return nil
}

func (v *view) closeLocked() {
	if v.closed {
		return
	}
	v.closed = true
	close(v.done)
	if v.in.current == v {
		v.in.current = nil
		v.in.controls = newControls(v.in.escape)
	}
}

func (v *view) isClosed() bool {
	select {
	case <-v.done:
		return true
	default:
		return false
	}
}
