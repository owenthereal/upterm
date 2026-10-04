package tui

import (
	"os"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// TestMain pins what the package reads from stdout, so the tests see the same
// thing whether `go test` runs from a terminal or a pipe: stdout is not a
// terminal, it is 80 columns wide, and lipgloss emits no colour codes.
func TestMain(m *testing.M) {
	stdoutIsTerminal = func() bool { return false }
	getTermWidth = func() int { return 80 }
	renderer.SetColorProfile(termenv.Ascii)
	lipgloss.SetColorProfile(termenv.Ascii)

	os.Exit(m.Run())
}
