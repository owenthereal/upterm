package client

import (
	"context"
	"io"
	"os"

	"github.com/creack/pty"
)

const (
	EventTerminalAttached EventType = iota
	EventTerminalDetached
	EventTerminalWindowChanged
)

type EventType int

type Event struct {
	Type     EventType
	Terminal Terminal
}

type Terminal struct {
	ID     string
	Pty    *os.File
	Window Window
}

type Window struct {
	Width  int
	Height int
}

func NewEventManager(ctx context.Context) *EventManager {
	return &EventManager{
		tmCh: make(chan Event),
		ctx:  ctx,
	}
}

type EventManager struct {
	tmCh chan Event
	ctx  context.Context
}

func (em *EventManager) HandleEvent() {
	go func() {
		<-em.ctx.Done()
		close(em.tmCh)
	}()

	m := make(map[io.ReadWriteCloser]map[string]Terminal)
	for evt := range em.tmCh {
		switch evt.Type {
		case EventTerminalAttached, EventTerminalWindowChanged:
			pty := evt.Terminal.Pty
			ts, ok := m[pty]
			if !ok {
				ts = make(map[string]Terminal)
				m[pty] = ts
			}
			ts[evt.Terminal.ID] = evt.Terminal
			resizeWindow(evt.Terminal.Pty, ts)
		case EventTerminalDetached:
			pty := evt.Terminal.Pty
			ts, ok := m[pty]
			if ok {
				delete(ts, evt.Terminal.ID)
			}

			if len(ts) == 0 {
				delete(m, pty)
			}
		}
	}
}

func (em *EventManager) TerminalEvent(id string, pty *os.File) *TerminalEventManager {
	return &TerminalEventManager{
		id:  id,
		pty: pty,
		ch:  em.tmCh,
		ctx: em.ctx,
	}
}

type TerminalEventManager struct {
	id  string
	pty *os.File
	ch  chan Event
	ctx context.Context
}

func (em *TerminalEventManager) send(evt Event) {
	// exit early
	select {
	case <-em.ctx.Done():
		return
	default:
	}

	select {
	case em.ch <- evt:
	case <-em.ctx.Done():
		return
	}
}

func (em *TerminalEventManager) TerminalAttached(width, height int) {
	em.send(Event{
		Type: EventTerminalAttached,
		Terminal: Terminal{
			ID:  em.id,
			Pty: em.pty,
			Window: Window{
				Width:  width,
				Height: height,
			},
		},
	})
}

func (em *TerminalEventManager) TerminalDetached() {
	em.send(Event{
		Type: EventTerminalDetached,
		Terminal: Terminal{
			ID:  em.id,
			Pty: em.pty,
		},
	})
}

func (em *TerminalEventManager) TerminalWindowChanged(width, height int) {
	em.send(Event{
		Type: EventTerminalWindowChanged,
		Terminal: Terminal{
			ID:  em.id,
			Pty: em.pty,
			Window: Window{
				Width:  width,
				Height: height,
			},
		},
	})
}

func resizeWindow(ptmx *os.File, ts map[string]Terminal) error {
	var w, h int

	for _, t := range ts {
		if w == 0 || w > t.Window.Width {
			w = t.Window.Width
		}

		if h == 0 || h > t.Window.Height {
			h = t.Window.Height
		}
	}

	size := &pty.Winsize{
		Rows: uint16(h),
		Cols: uint16(w),
	}

	return pty.Setsize(ptmx, size)
}
