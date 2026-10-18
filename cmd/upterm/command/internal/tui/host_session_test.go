package tui

import (
	"context"
	"io"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

// runPrompt runs the asking prompt in a program with no terminal, and returns
// what Program.Run does once it has been sent msgs. The program has no signal
// handler of its own, and no test here signals the process: a signal is the
// message bubbletea turns it into, tea.QuitMsg for SIGTERM and
// tea.InterruptMsg for SIGINT.
func runPrompt(t *testing.T, msgs ...tea.Msg) (HostSessionModel, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := tea.NewProgram(NewHostSessionModel(false),
		tea.WithContext(ctx), tea.WithInput(nil), tea.WithOutput(io.Discard), tea.WithoutSignalHandler())
	go func() {
		for _, m := range msgs {
			p.Send(m)
		}
	}()
	final, err := p.Run()
	m, ok := final.(HostSessionModel)
	require.True(t, ok, "%T", final)
	return m, err
}

// SIGTERM is a QuitMsg, and Run returns the model with no error: a prompt
// nobody answered, which must not read as the accepted one it started as.
func TestAPromptQuitWithoutAnAnswerIsNotAccepted(t *testing.T) {
	m, err := runPrompt(t, tea.QuitMsg{})
	require.NoError(t, err)
	require.NotEqual(t, HostSessionConfirmAccepted, m.Result())
	require.Equal(t, HostSessionConfirmUndecided, m.Result())
}

func TestThePromptsAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		msg  tea.Msg
		want HostSessionConfirmResult
	}{
		"y":      {tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}}, HostSessionConfirmAccepted},
		"n":      {tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}}, HostSessionConfirmRejected},
		"ctrl+c": {tea.KeyMsg{Type: tea.KeyCtrlC}, HostSessionConfirmInterrupted},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := runPrompt(t, tc.msg)
			require.NoError(t, err)
			require.Equal(t, tc.want, m.Result())
		})
	}
}

// SIGINT is an InterruptMsg: Run returns an error that wraps ErrInterrupted,
// which is how displaySession knows it.
func TestAnInterruptedPromptReturnsErrInterrupted(t *testing.T) {
	_, err := runPrompt(t, tea.InterruptMsg{})
	require.ErrorIs(t, err, tea.ErrInterrupted)
}

// --accept never asks: its model is the accepted one.
func TestAnAutoAcceptModelIsAccepted(t *testing.T) {
	require.Equal(t, HostSessionConfirmAccepted, NewHostSessionModel(true).Result())
}

// The banner is printed once, before the prompt, so all the prompt draws is
// its own line; and once answered it draws nothing, which clears that line on
// a y and leaves nothing behind on an n or a Ctrl-C.
func TestThePromptDrawsOnlyItsOwnLine(t *testing.T) {
	m := NewHostSessionModel(false)
	require.Equal(t, "Start the session? [y/n]", m.View())

	for name, key := range map[string]tea.KeyMsg{
		"y":      {Type: tea.KeyRunes, Runes: []rune{'y'}},
		"n":      {Type: tea.KeyRunes, Runes: []rune{'n'}},
		"ctrl+c": {Type: tea.KeyCtrlC},
	} {
		t.Run(name, func(t *testing.T) {
			answered, _ := m.Update(key)
			require.Empty(t, answered.View())
		})
	}
}
