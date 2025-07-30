package main

import (
	"github.com/owenthereal/upterm/cmd/upterm/command"
	"github.com/owenthereal/upterm/internal/version"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra/doc"
)

func main() {
	rootCmd := command.Root()

	if err := doc.GenMarkdownTree(rootCmd, "./docs"); err != nil {
		log.Fatal(err)
	}

	header := &doc.GenManHeader{
		Title:   "UPTERM",
		Section: "1",
		Source:  "Upterm " + version.String(),
		Manual:  "Upterm Manual",
	}
	if err := doc.GenManTree(rootCmd, header, "./etc/man/man1"); err != nil {
		log.Fatal(err)
	}

	if err := rootCmd.GenBashCompletionFile("./etc/completion/upterm.bash_completion.sh"); err != nil {
		log.Fatal(err)
	}
	if err := rootCmd.GenZshCompletionFile("./etc/completion/upterm.zsh_completion"); err != nil {
		log.Fatal(err)
	}
}
