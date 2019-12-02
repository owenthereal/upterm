package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jingweno/upterm/client"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/google/shlex"
)

var (
	flagHost           string
	flagAttachCommand  string
	flagKeepAlive      uint8
	flagPrivateKeys    []string
	flagAuthorizedKeys string

	rootCmd = &cobra.Command{
		Use:  "upterm",
		Long: "Share a terminal session.",
		Example: `  # Run $SHELL and client will attach to host's stdin, stdout and stderr
  upterm
  # Run 'bash' and client will attach with to host's stdin, stdout and stderr
  upterm bash
  # Run 'tmux new pair' and client will attach with 'tmux attach -t pair' after it connects
  upterm -t 'tmux attach -t pair' -- tmux new -t pair`,
		RunE: runE,
	}

	logger *log.Logger
)

func init() {
	logger = log.New()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		logger.Fatal(err)
	}

	rootCmd.PersistentFlags().StringVarP(&flagHost, "host", "", "127.0.0.1:2222", "server host")
	rootCmd.PersistentFlags().StringVarP(&flagAttachCommand, "attach-command", "t", "", "attach command after client connects")
	rootCmd.PersistentFlags().Uint8VarP(&flagKeepAlive, "keep-alive", "", 30, "server keep alive duration in second")
	rootCmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "a file from which the private key for public key authentication is read")
	rootCmd.PersistentFlags().StringVarP(&flagAuthorizedKeys, "authorized-keys", "a", "", "a file which lists public keys that are permitted to connect. This file is in the format of authorized_keys in OpenSSH.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}

func runE(c *cobra.Command, args []string) error {
	var err error
	if len(args) == 0 {
		args, err = shlex.Split(os.Getenv("SHELL"))
		if err != nil {
			return err
		}
	}

	var attachCommand []string
	if flagAttachCommand != "" {
		attachCommand, err = shlex.Split(flagAttachCommand)
		if err != nil {
			return fmt.Errorf("error parsing command %s: %w", flagAttachCommand, err)
		}
	}

	var authorizedKeys []ssh.PublicKey
	if flagAuthorizedKeys != "" {
		authorizedKeys, err = client.AuthorizedKeys(flagAuthorizedKeys)
	}
	if err != nil {
		return fmt.Errorf("error reading %s: %w", flagPrivateKeys, err)
	}

	auths, cleanup, err := client.AuthMethods(flagPrivateKeys)
	if err != nil {
		return fmt.Errorf("error reading private keys: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	client := client.NewClient(args, attachCommand, flagHost, auths, authorizedKeys, time.Duration(flagKeepAlive), logger)
	if err := printJoinCmd(client.ClientID()); err != nil {
		return err
	}
	defer logger.Info("Bye!")

	return client.Run(context.Background())
}

func printJoinCmd(sessionID string) error {
	host, port, err := net.SplitHostPort(flagHost)
	if err != nil {
		return err
	}

	cmd := fmt.Sprintf("ssh session: ssh -o ServerAliveInterval=%d %s@%s", flagKeepAlive, sessionID, host)
	if port != "22" {
		cmd = fmt.Sprintf("%s -p %s", cmd, port)
	}

	logger.Info(cmd)

	return nil
}

func defaultAuthorizedKeys(homeDir string) string {
	return filepath.Join(homeDir, ".ssh", "authorized_keys")
}

func defaultPrivateKeys(homeDir string) []string {
	var pks []string
	for _, f := range []string{
		"id_dsa",
		"id_ecdsa",
		"id_ed25519",
		"id_rsa",
	} {
		pk := filepath.Join(homeDir, ".ssh", f)
		if _, err := os.Stat(pk); os.IsNotExist(err) {
			continue
		}

		pks = append(pks, pk)
	}

	return pks
}
