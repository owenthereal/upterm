package command

import (
	"fmt"

	"github.com/owenthereal/upterm/upterm"
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		RunE: func(c *cobra.Command, args []string) error {
			_, err := fmt.Printf("Upterm version v%s\n", upterm.Version)
			return err
		},
	}

	return cmd
}
