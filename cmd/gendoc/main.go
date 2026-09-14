package main

import (
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra/doc"
)

func main() {
	logger := logging.Must(logging.Console()).With("component", "gendoc")
	defer func() {
		_ = logger.Close()
	}()

	// Note: XDG environment variables should be set externally before running this command
	// to generate docs with generic paths instead of machine-specific paths.
	// See Makefile 'docs' target for proper environment variable setup.
	rootCmd := command.Root()

	if err := doc.GenMarkdownTree(rootCmd, "./docs"); err != nil {
		logger.Error("failed generating markdown docs", "error", err)
		os.Exit(1)
	}

	header := &doc.GenManHeader{
		Title:   "UPTERM",
		Section: "1",
		Source:  "Upterm " + version.String(),
		Manual:  "Upterm Manual",
	}
	if err := doc.GenManTree(rootCmd, header, "./etc/man/man1"); err != nil {
		logger.Error("failed generating man pages", "error", err)
		os.Exit(1)
	}

	if err := rootCmd.GenBashCompletionFile("./etc/completion/upterm.bash_completion.sh"); err != nil {
		logger.Error("failed generating bash completion", "error", err)
		os.Exit(1)
	}
	if err := rootCmd.GenZshCompletionFile("./etc/completion/upterm.zsh_completion"); err != nil {
		logger.Error("failed generating zsh completion", "error", err)
		os.Exit(1)
	}
}
