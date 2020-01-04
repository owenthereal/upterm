package internal

import (
	"context"
	"io"

	log "github.com/sirupsen/logrus"
)

const (
	eventTerminalAttached eventType = iota
	eventTerminalDetached
	eventTerminalWindowChanged
)

type eventType int

type event struct {
	Type     eventType
	Terminal terminal
}

type terminal struct {
	ID     string
	Pty    *pty
	Window window
}

type window struct {
	Width  int
	Height int
}

func newEventManager(ctx context.Context, logger log.FieldLogger) *eventManager {
	return &eventManager{
		tmCh:   make(chan event),
		ctx:    ctx,
		logger: logger,
	}
}

type eventManager struct {
	tmCh   chan event
	ctx    context.Context
	logger log.FieldLogger
}

func (em *eventManager) HandleEvent() {
	m := make(map[io.ReadWriteCloser]map[string]terminal)
	for {
		select {
		case <-em.ctx.Done():
			close(em.tmCh)
			return
		case evt := <-em.tmCh:
			switch evt.Type {
			case eventTerminalAttached, eventTerminalWindowChanged:
				pty := evt.Terminal.Pty
				ts, ok := m[pty]
				if !ok {
					ts = make(map[string]terminal)
					m[pty] = ts
				}
				ts[evt.Terminal.ID] = evt.Terminal
				if err := resizeWindow(evt.Terminal.Pty, ts); err != nil {
					log.WithError(err).Debug("error resizing window")
				}
			case eventTerminalDetached:
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

func (em *eventManager) TerminalEvent(id string, pty *pty) *terminalEventManager {
	return &terminalEventManager{
		id:  id,
		pty: pty,
		ch:  em.tmCh,
		ctx: em.ctx,
	}
}

type terminalEventManager struct {
	id  string
	pty *pty
	ch  chan event
	ctx context.Context
}

func (em *terminalEventManager) send(evt event) {
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

func (em *terminalEventManager) TerminalAttached(width, height int) {
	em.send(event{
		Type: eventTerminalAttached,
		Terminal: terminal{
			ID:  em.id,
			Pty: em.pty,
			Window: window{
				Width:  width,
				Height: height,
			},
		},
	})
}

func (em *terminalEventManager) TerminalDetached() {
	em.send(event{
		Type: eventTerminalDetached,
		Terminal: terminal{
			ID:  em.id,
			Pty: em.pty,
		},
	})
}

func (em *terminalEventManager) TerminalWindowChanged(width, height int) {
	em.send(event{
		Type: eventTerminalWindowChanged,
		Terminal: terminal{
			ID:  em.id,
			Pty: em.pty,
			Window: window{
				Width:  width,
				Height: height,
			},
		},
	})
}

func resizeWindow(ptmx *pty, ts map[string]terminal) error {
	var w, h int

	for _, t := range ts {
		if w == 0 || w > t.Window.Width {
			w = t.Window.Width
		}

		if h == 0 || h > t.Window.Height {
			h = t.Window.Height
		}
	}

	return ptmx.Setsize(h, w)
}
