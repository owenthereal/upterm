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
	detail     SessionDetail
	autoAccept bool
	state      sessionState
	result     HostSessionConfirmResult
	width      int
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
func NewHostSessionModel(detail SessionDetail, autoAccept bool) HostSessionModel {
	initialState := stateWaitingForConfirm
	if autoAccept {
		initialState = stateDone
	}

	return HostSessionModel{
		detail:     detail,
		autoAccept: autoAccept,
		state:      initialState,
		result:     HostSessionConfirmAccepted, // default for auto-accept
		width:      getTermWidth(),
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
	case tea.WindowSizeMsg:
		m.width = msg.Width

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

func (m HostSessionModel) View() string {
	var b strings.Builder

	// Session info
	b.WriteString(renderSessionDetail(m.detail, m.width))

	if !IsTTY() {
		return b.String()
	}

	switch m.state {
	case stateWaitingForConfirm:
		b.WriteString("\n")
		b.WriteString(FooterStyle.Render("Accept connections? [y/n] (or <ctrl-c> to force exit)"))
		b.WriteString("\n")

	case stateDone:
		b.WriteString("\n")
		switch m.result {
		case HostSessionConfirmAccepted:
			b.WriteString(CommandStyle.Render("Starting to accept connections..."))
			b.WriteString("\n\n")
			b.WriteString(FooterStyle.Render("💡 Run 'upterm session current' to display session info"))
		case HostSessionConfirmRejected:
			b.WriteString(FooterStyle.Render("Session discarded."))
		case HostSessionConfirmInterrupted:
			b.WriteString(FooterStyle.Render("Cancelled by user."))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// Result returns the confirmation result
func (m HostSessionModel) Result() HostSessionConfirmResult {
	return m.result
}
