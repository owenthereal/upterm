package main

import (
	"github.com/jingweno/upterm/cmd/upterm/command"
	log "github.com/sirupsen/logrus"
)

func main() {
	rootCmd := command.Root()
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
