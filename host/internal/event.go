package internal

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/olebedev/emitter"
	"github.com/owenthereal/upterm/upterm"
	log "github.com/sirupsen/logrus"
)

const (
	errBadFileDescriptor = "bad file descriptor"
)

type terminal struct {
	ID     string
	Pty    *pty
	Window window
}

type window struct {
	Width  int
	Height int
}

type terminalEventEmitter struct {
	eventEmitter *emitter.Emitter
}

func (t terminalEventEmitter) TerminalWindowChanged(id string, pty *pty, w, h int) {
	tt := terminal{
		ID:  id,
		Pty: pty,
		Window: window{
			Width:  w,
			Height: h,
		},
	}
	t.eventEmitter.Emit(upterm.EventTerminalWindowChanged, tt)
}

func (t terminalEventEmitter) TerminalDetached(id string, pty *pty) {
	tt := terminal{
		ID:  id,
		Pty: pty,
	}
	t.eventEmitter.Emit(upterm.EventTerminalDetached, tt)
}

type terminalEventHandler struct {
	eventEmitter *emitter.Emitter
	logger       log.FieldLogger
}

func (t terminalEventHandler) Handle(ctx context.Context) error {
	winCh := t.eventEmitter.On(upterm.EventTerminalWindowChanged, emitter.Sync, emitter.Skip)
	dtCh := t.eventEmitter.On(upterm.EventTerminalDetached, emitter.Sync, emitter.Skip)

	defer func() {
		t.eventEmitter.Off(upterm.EventTerminalWindowChanged, winCh)
		t.eventEmitter.Off(upterm.EventTerminalDetached, dtCh)
	}()

	m := make(map[io.ReadWriteCloser]map[string]terminal)
	for {
		select {
		case evt := <-winCh:
			if err := t.handleWindowChanged(evt, m); err != nil {
				t.logger.WithError(err).Error("error handling window changed")
			}
		case evt := <-dtCh:
			if err := t.handleTerminalDetached(evt, m); err != nil {
				t.logger.WithError(err).Error("error handling terminal detached")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t terminalEventHandler) handleWindowChanged(evt emitter.Event, m map[io.ReadWriteCloser]map[string]terminal) error {
	args := evt.Args
	if len(args) == 0 {
		return fmt.Errorf("expect terminal window change event to have at least one argument")
	}

	tt, ok := args[0].(terminal)
	if !ok {
		return fmt.Errorf("expect terminal window change event to receive a terminal")
	}

	pty := tt.Pty
	ts, ok := m[pty]
	if !ok {
		ts = make(map[string]terminal)
		m[pty] = ts
	}
	ts[tt.ID] = tt
	if err := resizeWindow(pty, ts); err != nil && !strings.Contains(err.Error(), errBadFileDescriptor) {
		return fmt.Errorf("error resizing window: %w", err)
	}

	return nil
}

func (t terminalEventHandler) handleTerminalDetached(evt emitter.Event, m map[io.ReadWriteCloser]map[string]terminal) error {
	args := evt.Args
	if len(args) == 0 {
		return fmt.Errorf("expect terminal window change event to have at least one argument")
	}

	tt, ok := args[0].(terminal)
	if !ok {
		return fmt.Errorf("expect terminal window change event to receive a terminal")
	}

	pty := tt.Pty
	ts, ok := m[pty]
	if ok {
		delete(ts, tt.ID)
	}

	if len(ts) == 0 {
		delete(m, pty)
	}

	return nil
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
