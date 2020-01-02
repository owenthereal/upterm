package main

import (
	"github.com/jingweno/upterm/cmd/upterm/command"
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
		Source:  "Upterm " + command.Version,
		Manual:  "Upterm Manual",
	}
	if err := doc.GenManTree(rootCmd, header, "./etc/man1"); err != nil {
		log.Fatal(err)
	}

	if err := rootCmd.GenBashCompletionFile("./etc/upterm.bash_completion.sh"); err != nil {
		log.Fatal(err)
	}
	if err := rootCmd.GenZshCompletionFile("./etc/upterm.zsh_completion"); err != nil {
		log.Fatal(err)
	}
}
