package command

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "0.0.1"

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		RunE: func(c *cobra.Command, args []string) error {
			_, err := fmt.Printf("upterm version %s\n", Version)
			return err
		},
	}

	return cmd
}
