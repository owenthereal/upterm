package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// HostSessionConfirmResult represents the outcome of a confirmation prompt
type HostSessionConfirmResult int

const (
	// HostSessionConfirmUndecided indicates nobody answered: the prompt is
	// still open, or ended without an answer (bubbletea quits the program on
	// SIGTERM). It is the zero value so that nothing reads an unanswered
	// prompt as an acceptance.
	HostSessionConfirmUndecided HostSessionConfirmResult = iota
	// HostSessionConfirmAccepted indicates the user accepted (pressed 'y')
	HostSessionConfirmAccepted
	// HostSessionConfirmRejected indicates the user rejected (pressed 'n')
	HostSessionConfirmRejected
	// HostSessionConfirmInterrupted indicates the user interrupted (pressed Ctrl+C)
	HostSessionConfirmInterrupted
)

// HostSessionModel asks the host whether to start the session (y/n/Ctrl+C)
// unless auto-accept is enabled. The banner is printed once before it runs,
// so the prompt line is all it draws: a redraw repaints that line and nothing
// above it.
type HostSessionModel struct {
	autoAccept bool
	state      sessionState
	result     HostSessionConfirmResult
}

// sessionState represents the current state of the host session prompt
type sessionState int

const (
	// stateWaitingForConfirm indicates we're displaying the prompt and waiting for user input
	stateWaitingForConfirm sessionState = iota
	// stateDone indicates a decision has been made and we're ready to quit
	stateDone
)

// NewHostSessionModel creates a model that asks whether to start the session
func NewHostSessionModel(autoAccept bool) HostSessionModel {
	initialState := stateWaitingForConfirm
	result := HostSessionConfirmUndecided
	if autoAccept {
		initialState = stateDone
		result = HostSessionConfirmAccepted
	}

	return HostSessionModel{
		autoAccept: autoAccept,
		state:      initialState,
		result:     result,
	}
}

func (m HostSessionModel) Init() tea.Cmd {
	// Auto-quit immediately if auto-accept is enabled
	if m.autoAccept {
		return tea.Quit
	}
	return nil
}

func (m HostSessionModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Only handle input when waiting for confirmation
		if m.state != stateWaitingForConfirm {
			return m, nil
		}

		switch msg.String() {
		case "y", "Y":
			m.result = HostSessionConfirmAccepted
			m.state = stateDone
			return m, tea.Quit
		case "n", "N":
			m.result = HostSessionConfirmRejected
			m.state = stateDone
			return m, tea.Quit
		case "ctrl+c":
			m.result = HostSessionConfirmInterrupted
			m.state = stateDone
			return m, tea.Quit
		}
	}

	return m, nil
}

// View is the prompt while it waits, and nothing once it is answered: the
// renderer clears the line on the way out, so a y leaves no trace of the
// question above the session, and an n or a Ctrl-C leaves nothing at all.
func (m HostSessionModel) View() string {
	if m.state != stateWaitingForConfirm {
		return ""
	}
	return FooterStyle.Render("Start the session? [y/n]")
}

// Result returns the confirmation result
func (m HostSessionModel) Result() HostSessionConfirmResult {
	return m.result
}
