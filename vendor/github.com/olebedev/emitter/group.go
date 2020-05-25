package emitter

import (
	"reflect"
	"sync"
)

// Group marges given subscribed channels into
// on subscribed channel
type Group struct {
	// Cap is capacity to create new channel
	Cap uint

	mu        sync.Mutex
	listeners []listener
	isInit    bool

	stop chan struct{}
	done chan struct{}

	cmu   sync.Mutex
	cases []reflect.SelectCase

	lmu      sync.Mutex
	isListen bool
}

// Flush reset the group to the initial state.
// All references will dropped.
func (g *Group) Flush() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopIfListen()
	close(g.stop)
	close(g.done)
	g.isInit = false
	g.init()
}

// Add adds channels which were already subscribed to
// some events.
func (g *Group) Add(channels ...<-chan Event) {
	g.mu.Lock()
	defer g.listen()
	defer g.mu.Unlock()
	g.init()

	g.stopIfListen()

	g.cmu.Lock()
	cases := make([]reflect.SelectCase, len(channels))
	for i, ch := range channels {
		cases[i] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		}
	}
	g.cases = append(g.cases, cases...)
	g.cmu.Unlock()
}

// On returns subscribed channel.
func (g *Group) On() <-chan Event {
	g.mu.Lock()
	defer g.listen()
	defer g.mu.Unlock()
	g.init()

	g.stopIfListen()

	l := newListener(g.Cap)
	g.listeners = append(g.listeners, l)
	return l.ch
}

// Off unsubscribed given channels if any or unsubscribed all
// channels in other case
func (g *Group) Off(channels ...<-chan Event) {
	g.mu.Lock()
	defer g.listen()
	defer g.mu.Unlock()
	g.init()

	g.stopIfListen()

	if len(channels) != 0 {
		for _, ch := range channels {
			i := -1
		Listeners:
			for in := range g.listeners {
				if g.listeners[in].ch == ch {
					i = in
					break Listeners
				}
			}
			if i != -1 {
				l := g.listeners[i]
				g.listeners = append(g.listeners[:i], g.listeners[i+1:]...)
				close(l.ch)
			}
		}
	} else {
		g.listeners = make([]listener, 0)
	}
}

func (g *Group) stopIfListen() bool {
	g.lmu.Lock()
	defer g.lmu.Unlock()

	if !g.isListen {
		return false
	}

	g.stop <- struct{}{}
	g.isListen = false
	return true
}

func (g *Group) listen() {
	g.lmu.Lock()
	defer g.lmu.Unlock()
	g.cmu.Lock()
	g.isListen = true

	go func() {
		// unlock cases and isListen flag when func is exit
		defer g.cmu.Unlock()

		for {
			i, val, isOpened := reflect.Select(g.cases)

			// exit if listening is stopped
			if i == 0 {
				return
			}

			if !isOpened && len(g.cases) > i {
				// remove this case
				g.cases = append(g.cases[:i], g.cases[i+1:]...)
			}

			e := val.Interface().(Event)
			// use unblocked mode
			e.Flags = e.Flags | FlagSkip
			// send events to all listeners
			g.mu.Lock()
			for index := range g.listeners {
				l := g.listeners[index]
				pushEvent(g.done, l.ch, &e)
			}
			g.mu.Unlock()
		}
	}()
}

func (g *Group) init() {
	if g.isInit {
		return
	}
	g.stop = make(chan struct{})
	g.done = make(chan struct{})
	g.cases = []reflect.SelectCase{
		{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(g.stop),
		},
	}
	g.listeners = make([]listener, 0)
	g.isInit = true
}
