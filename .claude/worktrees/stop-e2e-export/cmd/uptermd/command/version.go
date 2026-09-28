package command

import (
	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		RunE: func(c *cobra.Command, args []string) error {
			version.PrintVersion("Uptermd")
			return nil
		},
	}

	return cmd
}
