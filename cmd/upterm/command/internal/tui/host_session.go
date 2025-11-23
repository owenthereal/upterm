package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// HostSessionConfirmResult represents the outcome of a confirmation prompt
type HostSessionConfirmResult int

const (
	// HostSessionConfirmAccepted indicates the user accepted (pressed 'y')
	HostSessionConfirmAccepted HostSessionConfirmResult = iota
	// HostSessionConfirmRejected indicates the user rejected (pressed 'n')
	HostSessionConfirmRejected
	// HostSessionConfirmInterrupted indicates the user interrupted (pressed Ctrl+C)
	HostSessionConfirmInterrupted
)

// HostSessionModel handles both session display and confirmation for the host command.
// It renders the session information and waits for user confirmation (y/n/Ctrl+C)
// unless auto-accept is enabled.
type HostSessionModel struct {
	sessionOutput string // Pre-rendered session info
	autoAccept    bool
	state         sessionState
	result        HostSessionConfirmResult
}

// sessionState represents the current state of the host session prompt
type sessionState int

const (
	// stateWaitingForConfirm indicates we're displaying the prompt and waiting for user input
	stateWaitingForConfirm sessionState = iota
	// stateDone indicates a decision has been made and we're ready to quit
	stateDone
)

// NewHostSessionModel creates a model for displaying session and getting confirmation
func NewHostSessionModel(sessionOutput string, autoAccept bool) HostSessionModel {
	initialState := stateWaitingForConfirm
	if autoAccept {
		initialState = stateDone
	}

	return HostSessionModel{
		sessionOutput: sessionOutput,
		autoAccept:    autoAccept,
		state:         initialState,
		result:        HostSessionConfirmAccepted, // default for auto-accept
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
	// Only handle input when waiting for confirmation
	// Note: Context cancellation is handled automatically by tea.Program
	if m.state != stateWaitingForConfirm {
		return m, nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
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

func (m HostSessionModel) View() string {
	var b strings.Builder

	// Always show the session info
	b.WriteString(m.sessionOutput)

	switch m.state {
	case stateWaitingForConfirm:
		b.WriteString("\n🤝 Accept connections? [y/n] (or <ctrl-c> to force exit)\n")

	case stateDone:
		b.WriteString("\n")
		switch m.result {
		case HostSessionConfirmAccepted:
			b.WriteString("✅ Starting to accept connections...\n")
		case HostSessionConfirmRejected:
			b.WriteString("❌ Session discarded.\n")
		case HostSessionConfirmInterrupted:
			b.WriteString("Cancelled by user.\n")
		}
	}

	return b.String()
}

// Result returns the confirmation result
func (m HostSessionModel) Result() HostSessionConfirmResult {
	return m.result
}
