package command

import (
	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Args:  cobra.ExactArgs(0),
		// A broken config file doesn't stop it.
		Annotations: map[string]string{annotationConfig: "none"},
		RunE: func(c *cobra.Command, args []string) error {
			version.PrintVersion("Upterm")
			return nil
		},
	}

	return cmd
}
