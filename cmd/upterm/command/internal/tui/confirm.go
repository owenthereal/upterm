package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// ConfirmResult represents the outcome of a confirmation prompt
type ConfirmResult int

const (
	// ConfirmAccepted indicates the user accepted (pressed 'y')
	ConfirmAccepted ConfirmResult = iota
	// ConfirmRejected indicates the user rejected (pressed 'n')
	ConfirmRejected
	// ConfirmInterrupted indicates the user interrupted (pressed Ctrl+C)
	ConfirmInterrupted
)

// ConfirmModel is a simple Bubbletea model for y/n confirmation prompts
type ConfirmModel struct {
	prompt string
	result ConfirmResult
}

// NewConfirmModel creates a new confirmation model with the given prompt text
func NewConfirmModel(prompt string) ConfirmModel {
	return ConfirmModel{
		prompt: prompt,
		result: ConfirmAccepted, // default to accepted
	}
}

// Init initializes the model (no commands needed)
func (m ConfirmModel) Init() tea.Cmd {
	return nil
}

// Update handles keyboard input and determines the confirmation result
func (m ConfirmModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			m.result = ConfirmAccepted
			return m, tea.Quit
		case "n", "N":
			m.result = ConfirmRejected
			return m, tea.Quit
		case "ctrl+c":
			m.result = ConfirmInterrupted
			return m, tea.Quit
		}
	}
	return m, nil
}

// View renders the prompt text
func (m ConfirmModel) View() string {
	return m.prompt
}

// Result returns the confirmation result after the program has quit
func (m ConfirmModel) Result() ConfirmResult {
	return m.result
}
