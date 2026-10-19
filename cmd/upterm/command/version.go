package command

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/owenthereal/upterm/internal/version"
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Long: `Print upterm's version, with its git commit and build date when known.

Exit status: 0, or 1 on failure.`,
		Args: cobra.ExactArgs(0),
		// A broken config file doesn't stop it.
		Annotations: map[string]string{annotationConfig: "none"},
		RunE: func(c *cobra.Command, args []string) error {
			switch output {
			case "":
				version.PrintVersion("Upterm")
				return nil
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(version.GetBuildInfo())
			default:
				return fmt.Errorf("invalid output format %q: must be 'json'", output)
			}
		},
	}

	// Only the command line sets it: an output key or UPTERM_OUTPUT is meant
	// for the commands that take one, and must neither turn the version into
	// JSON nor make it fail.
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output format: json, with version, gitCommit and buildDate (command line only)")
	_ = cmd.RegisterFlagCompletionFunc("output", completeValues("json"))
	_ = cmd.Flags().SetAnnotation("output", annotationCLIOnly, []string{"true"})

	return cmd
}
