package command

import (
	"github.com/spf13/cobra"
)

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm daemon",
	}

	rootCmd.AddCommand(serverCmd())
	rootCmd.AddCommand(routerCmd())

	return rootCmd
}
