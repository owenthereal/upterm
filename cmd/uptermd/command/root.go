package command

import (
	"fmt"
	"os"
	"strings"

	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func Root(logger log.FieldLogger) *cobra.Command {
	rootCmd := &rootCmd{}
	cmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm Daemon",
		RunE:  rootCmd.Run,
	}

	cmd.PersistentFlags().String("config", "", "server config")

	cmd.PersistentFlags().StringP("ssh-addr", "", utils.DefaultLocalhost("2222"), "ssh server address")
	cmd.PersistentFlags().StringP("ws-addr", "", "", "websocket server address")
	cmd.PersistentFlags().StringP("node-addr", "", "", "node address")
	cmd.PersistentFlags().StringSliceP("private-key", "", nil, "server private key")
	cmd.PersistentFlags().StringSliceP("hostname", "", nil, "server hostname for public-key authentication certificate principals. If empty, public-key authentication is used instead.")

	cmd.PersistentFlags().StringP("network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceP("network-opt", "", nil, "network provider option")

	cmd.PersistentFlags().StringP("metric-addr", "", "", "metric server address")
	cmd.PersistentFlags().BoolP("debug", "", os.Getenv("DEBUG") != "", "debug")

	return cmd
}

type rootCmd struct {
}

func (cmd *rootCmd) Run(c *cobra.Command, args []string) error {
	var opt server.Opt
	if err := unmarshalFlags(c, &opt); err != nil {
		return err
	}

	return server.Start(opt)
}

func unmarshalFlags(cmd *cobra.Command, opts interface{}) error {
	v := viper.New()

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		flagName := flag.Name
		if flagName != "config" && flagName != "help" {
			if err := v.BindPFlag(flagName, flag); err != nil {
				panic(fmt.Errorf("error binding flag '%s': %w", flagName, err).Error())
			}
		}
	})

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.SetEnvPrefix("UPTERMD")

	cfgFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}

	if _, err := os.Stat(cfgFile); err == nil {
		v.SetConfigFile(cfgFile)
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error loading config file %s: %w", cfgFile, err)
		}
	}

	return v.Unmarshal(opts)
}
