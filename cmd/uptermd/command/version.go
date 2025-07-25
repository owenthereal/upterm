package command

import (
	"fmt"

	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		RunE: func(c *cobra.Command, args []string) error {
			_, err := fmt.Printf("Uptermd version v%s\n", version.String())
			return err
		},
	}

	return cmd
}