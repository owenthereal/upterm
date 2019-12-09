package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jingweno/upterm/host"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/google/shlex"
)

var (
	flagHost           string
	flagJoinCommand    string
	flagKeepAlive      uint8
	flagPrivateKeys    []string
	flagAuthorizedKeys string

	rootCmd = &cobra.Command{
		Use:  "upterm",
		Long: "Share a terminal session.",
		Example: `  # Host a session by running $SHELL. Client's input & output are attached to the host's.
  upterm
  # Host a session by running 'bash'. Client's input & output are attached to the host's.
  upterm bash
  # Host a session by running 'tmux new pair'. Client runs 'tmux attach -t pair' to attach to the session.
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
	rootCmd.PersistentFlags().StringVarP(&flagJoinCommand, "join-command", "j", "", "command to run after client joins, otherwise client is attached to host's input/output.")
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

	var joinCommand []string
	if flagJoinCommand != "" {
		joinCommand, err = shlex.Split(flagJoinCommand)
		if err != nil {
			return fmt.Errorf("error parsing command %s: %w", flagJoinCommand, err)
		}
	}

	var authorizedKeys []ssh.PublicKey
	if flagAuthorizedKeys != "" {
		authorizedKeys, err = host.AuthorizedKeys(flagAuthorizedKeys)
	}
	if err != nil {
		return fmt.Errorf("error reading %s: %w", flagPrivateKeys, err)
	}

	auths, cleanup, err := host.AuthMethods(flagPrivateKeys)
	if err != nil {
		return fmt.Errorf("error reading private keys: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	h := &host.Host{
		Host:           flagHost,
		SessionID:      xid.New().String(),
		Command:        args,
		JoinCommand:    joinCommand,
		Auths:          auths,
		AuthorizedKeys: authorizedKeys,
		KeepAlive:      time.Duration(flagKeepAlive),
		Logger:         logger,
	}
	if err := printJoinCmd(h.SessionID); err != nil {
		return err
	}
	defer logger.Info("Bye!")

	return h.Run(context.Background())
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
