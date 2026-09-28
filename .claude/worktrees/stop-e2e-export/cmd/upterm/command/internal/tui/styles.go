package tui

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

// renderer is bound to stdout for consistent style rendering
var renderer = lipgloss.NewRenderer(os.Stdout)

// Common styles used across TUI components
// Using basic ANSI colors (0-15) which adapt to terminal themes,
// ensuring readability on both light and dark backgrounds.
var (
	// Title/Header style - bright cyan, bold
	TitleStyle = renderer.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("14"))

	// Label style - white (terminal's default light color)
	LabelStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("7"))

	// Value style - bright white
	ValueStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("15"))

	// Command style - bright green, bold (for SSH commands)
	CommandStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("10")).
			Bold(true)

	// Footer style - dark gray
	FooterStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("8"))

	// Empty/placeholder style - dark gray, italic
	EmptyStyle = renderer.NewStyle().
			Foreground(lipgloss.Color("8")).
			Italic(true)
)
