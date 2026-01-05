package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

// renderer is bound to stdout for consistent style rendering
var renderer = lipgloss.NewRenderer(os.Stdout)

// Common styles used across TUI components
var (
	// Title/Header style - cyan, bold
	TitleStyle = renderer.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	// Label style - gray
	LabelStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("245"))

	// Value style - light gray
	ValueStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("252"))

	// Command style - green, bold (for SSH commands)
	CommandStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("42")).
			Bold(true)

	// Footer style - dim gray
	FooterStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("241"))

	// Empty/placeholder style - dim gray, italic
	EmptyStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("241")).
			Italic(true)
)
