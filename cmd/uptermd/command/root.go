package command

import (
	"fmt"
	"os"
	"strings"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func Root() *cobra.Command {
	rootCmd := &rootCmd{}
	cmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm Daemon",
		RunE:  rootCmd.RunE,
	}

	cmd.PersistentFlags().String("config", "", "server config")

	cmd.PersistentFlags().StringP("ssh-addr", "", utils.DefaultLocalhost("2222"), "ssh server address")
	cmd.PersistentFlags().StringP("ws-addr", "", "", "websocket server address")
	cmd.PersistentFlags().StringP("node-addr", "", "", "node address")
	cmd.PersistentFlags().StringSliceP("private-key", "", nil, "server private key")
	cmd.PersistentFlags().StringSliceP("hostname", "", nil, "server hostname for public-key authentication certificate principals. If empty, public-key authentication is used instead.")
	cmd.PersistentFlags().BoolP("ssh-proxy-protocol", "", false, "enable PROXY protocol support for the SSH listener (for use behind TCP proxies like Traefik, HAProxy, or AWS ELB)")

	cmd.PersistentFlags().StringP("network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceP("network-opt", "", nil, "network provider option")

	cmd.PersistentFlags().StringP("metric-addr", "", "", "metric server address")
	cmd.PersistentFlags().BoolP("debug", "", os.Getenv("DEBUG") != "", "debug")

	cmd.PersistentFlags().String("routing", string(routing.ModeEmbedded), "session routing mode")
	cmd.PersistentFlags().String("consul-url", "", "consul URL for routing mode 'consul'")
	cmd.PersistentFlags().String("consul-session-ttl", server.DefaultSessionTTL.String(), "consul session TTL for routing mode 'consul'")

	cmd.PersistentFlags().String("sentry-dsn", "", "Sentry DSN for error tracking")

	cmd.AddCommand(versionCmd())

	return cmd
}

type rootCmd struct {
}

func (cmd *rootCmd) RunE(c *cobra.Command, args []string) error {
	var opt server.Opt
	if err := unmarshalFlags(c, &opt); err != nil {
		return err
	}

	logOptions := []logging.Option{logging.Console()}
	if opt.Debug {
		logOptions = append(logOptions, logging.Debug())
	}
	if opt.SentryDSN != "" {
		logOptions = append(logOptions, logging.Sentry(opt.SentryDSN))
	}

	logger, err := logging.New(logOptions...)
	if err != nil {
		return err
	}
	defer func() {
		_ = logger.Close()
	}()

	c.SetContext(uptermctx.WithLogger(c.Context(), logger))

	if err := server.Start(c.Context(), opt, logger.Logger); err != nil {
		logger.Error("failed to start uptermd", "error", err)
		return fmt.Errorf("failed to start uptermd: %w", err)
	}

	return nil
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

	// Bind SENTRY_DSN directly (standard convention), with UPTERMD_SENTRY_DSN as fallback
	_ = v.BindEnv("sentry-dsn", "SENTRY_DSN", "UPTERMD_SENTRY_DSN")

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
