package main

import (
	"github.com/jingweno/upterm/cmd/upterm/internal/command"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "upterm",
		Short: "Instant terminal sharing",
	}

	rootCmd.AddCommand(command.Share())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
