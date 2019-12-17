package command

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/shlex"
	"github.com/jingweno/upterm/host"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	flagHost           string
	flagJoinCommand    string
	flagKeepAlive      uint8
	flagPrivateKeys    []string
	flagAuthorizedKeys string
)

func Share() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Share a terminal session",
		Example: `  # Share a session by running $SHELL. Client's input & output are attached to the host's.
  upterm share
  # Share a session by running 'bash'. Client's input & output are attached to the host's.
  upterm share bash
  # Share a session by running 'tmux new pair'. Client runs 'tmux attach -t pair' to attach to the session.
  upterm share -t 'tmux attach -t pair' -- tmux new -t pair`,
		RunE: shareRunE,
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	cmd.PersistentFlags().StringVarP(&flagHost, "host", "", "127.0.0.1:2222", "server host")
	cmd.PersistentFlags().StringVarP(&flagJoinCommand, "join-command", "j", "", "command to run after client joins, otherwise client is attached to host's input/output.")
	cmd.PersistentFlags().Uint8VarP(&flagKeepAlive, "keep-alive", "", 30, "server keep alive duration in second")
	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "a file from which the private key for public key authentication is read")
	cmd.PersistentFlags().StringVarP(&flagAuthorizedKeys, "authorized-keys", "a", "", "a file which lists public keys that are permitted to connect. This file is in the format of authorized_keys in OpenSSH.")

	return cmd
}

func shareRunE(c *cobra.Command, args []string) error {
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
		Logger:         log.New(),
	}
	if err := printJoinCmd(h.SessionID); err != nil {
		return err
	}
	defer log.Info("Bye!")

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

	log.Info(cmd)

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
