package event

import (
	"context"
	"io"

	"github.com/creack/pty"
	"github.com/jingweno/upterm/host/internal"
	log "github.com/sirupsen/logrus"
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
	Pty    *internal.Pty
	Window Window
}

type Window struct {
	Width  int
	Height int
}

func NewEventManager(ctx context.Context, logger log.FieldLogger) *EventManager {
	return &EventManager{
		tmCh:   make(chan Event),
		ctx:    ctx,
		logger: logger,
	}
}

type EventManager struct {
	tmCh   chan Event
	ctx    context.Context
	logger log.FieldLogger
}

func (em *EventManager) HandleEvent() {
	m := make(map[io.ReadWriteCloser]map[string]Terminal)
	for {
		select {
		case <-em.ctx.Done():
			close(em.tmCh)
			return
		case evt := <-em.tmCh:
			switch evt.Type {
			case EventTerminalAttached, EventTerminalWindowChanged:
				pty := evt.Terminal.Pty
				ts, ok := m[pty]
				if !ok {
					ts = make(map[string]Terminal)
					m[pty] = ts
				}
				ts[evt.Terminal.ID] = evt.Terminal
				if err := resizeWindow(evt.Terminal.Pty, ts); err != nil {
					log.WithError(err).Debug("error resizing window")
				}
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
}

func (em *EventManager) TerminalEvent(id string, pty *internal.Pty) *TerminalEventManager {
	return &TerminalEventManager{
		id:  id,
		pty: pty,
		ch:  em.tmCh,
		ctx: em.ctx,
	}
}

type TerminalEventManager struct {
	id  string
	pty *internal.Pty
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
	case <-em.ctx.Done():
		return
	case em.ch <- evt:
	default: // if channel is closed
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

func resizeWindow(ptmx *internal.Pty, ts map[string]Terminal) error {
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

	return ptmx.Setsize(size)
}
