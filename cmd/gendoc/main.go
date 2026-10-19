package main

import (
	"os"

	"github.com/owenthereal/upterm/cmd/upterm/command"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra"
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
	rootCmd := docRoot()

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

	if err := rootCmd.GenBashCompletionFileV2("./etc/completion/upterm.bash_completion.sh", true); err != nil {
		logger.Error("failed generating bash completion", "error", err)
		os.Exit(1)
	}
	if err := rootCmd.GenZshCompletionFile("./etc/completion/upterm.zsh_completion"); err != nil {
		logger.Error("failed generating zsh completion", "error", err)
		os.Exit(1)
	}
}

// docRoot is the command tree the pages describe. The root and the groups
// run only to report an unknown command, so their pages show no usage line
// of their own, as for a command that can't run, and a man page's synopsis,
// which cobra writes for every command, names their commands, as their
// --help does: upterm session [command].
func docRoot() *cobra.Command {
	root := command.Root()
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.HasSubCommands() {
			c.Run, c.RunE = nil, nil
			c.Use = c.Name() + " [command]"
			c.DisableFlagsInUseLine = true
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
	return root
}
