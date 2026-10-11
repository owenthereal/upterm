package join

import "github.com/owenthereal/upterm/internal/termsize"

// resizer passes the terminal's changes of size on to the session that is
// running, for the whole run. A value on the caller's channel only says that
// the size changed, since it may have been measured before the session's pty
// request and arrive after it: what the session gets is the size measured
// with Size as the change is taken. The resizer also measures the size each
// pty request carries, as it starts forwarding to the session, so every size
// a session gets was measured after its pty request's. A change taken while
// no session is running is dropped: the next pty request measures the size
// anew.
type resizer struct {
	changes <-chan termsize.Size
	// size measures the terminal. Nil: a change carries its own size, and a
	// pty request keeps the size it has.
	size func() termsize.Size

	// starts takes each session's forwarding as the session starts, and the
	// zero one as it ends; measured answers a start that asks for the size.
	starts   chan forwarding
	measured chan termsize.Size
	// quit closes with stop; done once run has returned.
	quit, done chan struct{}
}

// forwarding is where the changes go while a session runs: to, which the
// session reads, and whether to measure the size its pty request carries.
type forwarding struct {
	to      chan termsize.Size
	measure bool
}

func newResizer(changes <-chan termsize.Size, size func() termsize.Size) *resizer {
	f := &resizer{
		changes:  changes,
		size:     size,
		starts:   make(chan forwarding),
		measured: make(chan termsize.Size),
		quit:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go f.run()
	return f
}

// run takes every change as it comes, so the caller's sender is never held
// up for long, and measures every size, so the measurements are in order.
func (f *resizer) run() {
	defer close(f.done)
	var to chan termsize.Size
	for {
		select {
		case s, ok := <-f.changes:
			switch {
			case !ok:
				// Nothing more will come.
				f.changes = nil
			case to != nil:
				if f.size != nil {
					s = f.size()
				}
				offer(to, s)
			}
		case fw := <-f.starts:
			to = fw.to
			if fw.measure {
				f.measured <- f.size()
			}
		case <-f.quit:
			return
		}
	}
}

// begin forwards the changes to to, the channel of a session that is
// starting, from now until end. With measure, it returns the size for the
// session's pty request, measured after every change the session won't get
// and before every one it will; measure needs Size.
func (f *resizer) begin(to chan termsize.Size, measure bool) termsize.Size {
	f.starts <- forwarding{to: to, measure: measure}
	if !measure {
		return termsize.Size{}
	}
	return <-f.measured
}

// end stops forwarding to the session that began last: changes from now on
// come while no session is running.
func (f *resizer) end() { f.starts <- forwarding{} }

// stop ends the forwarding as Run returns: once it has, nothing reads the
// caller's channel or measures the size.
func (f *resizer) stop() {
	close(f.quit)
	<-f.done
}

// offer puts s on to in place of whatever size to still holds: a session that
// hasn't taken the last one needs only the latest. Only the resizer sends on
// to, so a place is free by the second try.
func offer(to chan termsize.Size, s termsize.Size) {
	for {
		select {
		case to <- s:
			return
		default:
		}
		select {
		case <-to:
		default:
		}
	}
}
