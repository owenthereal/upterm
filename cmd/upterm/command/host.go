package command

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/gen2brain/beeep"
	"github.com/google/shlex"
	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var (
	flagServer             string
	flagForceCommand       string
	flagPrivateKeys        []string
	flagKnownHostsFilename string
	flagAuthorizedKeys     string
	flagGitHubUsers        []string
	flagGitLabUsers        []string
	flagReadOnly           bool
	flagVSCode             bool
	flagVSCodeDir          string
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Host a terminal session",
		Long:  `Host a terminal session over a reverse SSH tunnel to the Upterm server with the IO of the host and the client attaching to the IO of a command. By default, the command authenticates against the Upterm server using the private key files located at ~/.ssh/id_dsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ed25519, and ~/.ssh/id_rsa. If no private key file is found, the command reads private keys from SSH Agent. If no private key is found from files or SSH Agent, the command falls back to generate one on the fly. To permit authorized clients to join, client public keys can be specified with --authorized-key.`,
		Example: `  # Host a terminal session that runs $SHELL with
  # client's input/output attaching to the host's
  upterm host

  # Host a terminal session that only allows specified public key(s) to connect
  upterm host --authorized-key PATH_TO_PUBLIC_KEY

  # Host a session with a custom command.
  upterm host -- docker run --rm -ti ubuntu bash

  # Host a session that runs 'tmux new -t pair-programming' and
  # force clients to join with 'tmux attach -t pair-programming'.
  # This is similar to tmate.
  upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming

  # Use a different Uptermd server and host a session via WebSocket
  upterm host --server wss://YOUR_UPTERMD_SERVER -- YOUR_COMMAND`,
		PreRunE: validateShareRequiredFlags,
		RunE:    shareRunE,
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	cmd.PersistentFlags().StringVarP(&flagServer, "server", "", "ssh://uptermd.upterm.dev:22", "upterm server address (required), supported protocols are ssh, ws, or wss.")
	cmd.PersistentFlags().StringVarP(&flagForceCommand, "force-command", "f", "", "force execution of a command and attach its input/output to client's.")
	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "private key file for public key authentication against the upterm server")
	cmd.PersistentFlags().StringVarP(&flagKnownHostsFilename, "known-hosts", "", defaultKnownHost(homeDir), "a file contains the known keys for remote hosts (required).")
	cmd.PersistentFlags().StringVarP(&flagAuthorizedKeys, "authorized-key", "a", "", "an authorized_keys file that lists public keys that are permitted to connect.")
	cmd.PersistentFlags().StringSliceVar(&flagGitHubUsers, "github-user", nil, "this GitHub user public keys are permitted to connect.")
	cmd.PersistentFlags().StringSliceVar(&flagGitLabUsers, "gitlab-user", nil, "this GitLab user public keys are permitted to connect.")
	cmd.PersistentFlags().BoolVar(&flagVSCode, "vscode", false, "allow vscode remote ssh connect")
	cmd.PersistentFlags().StringVar(&flagVSCodeDir, "vscode-dir", "/", "vscode remote ssh connect directory")
	cmd.PersistentFlags().BoolVarP(&flagReadOnly, "read-only", "r", false, "host a read-only session. Clients won't be able to interact.")

	return cmd
}

func validateShareRequiredFlags(c *cobra.Command, args []string) error {
	var result error

	if flagServer == "" {
		result = multierror.Append(result, fmt.Errorf("missing flag --server"))
	} else {
		u, err := url.Parse(flagServer)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("error pasring server URL: %w", err))
		}

		if u != nil {
			if u.Scheme != "ssh" && u.Scheme != "ws" && u.Scheme != "wss" {
				result = multierror.Append(result, fmt.Errorf("unsupported server protocol %s", u.Scheme))
			}

			if u.Scheme == "ssh" {
				_, _, err := net.SplitHostPort(u.Host)
				if err != nil {
					result = multierror.Append(result, err)
				}
			}

			// set default ports for ws or wss
			if u.Scheme == "ws" && u.Port() == "" {
				u.Host = u.Host + ":80"
				flagServer = u.String()
			}
			if u.Scheme == "wss" && u.Port() == "" {
				u.Host = u.Host + ":443"
				flagServer = u.String()
			}
		}
	}

	return result
}

func shareRunE(c *cobra.Command, args []string) error {
	var err error
	if len(args) == 0 {
		args, err = shlex.Split(os.Getenv("SHELL"))
		if err != nil {
			return err
		}

		if len(args) == 0 {
			return fmt.Errorf("no command is specified")
		}
	}

	var forceCommand []string
	if flagForceCommand != "" {
		forceCommand, err = shlex.Split(flagForceCommand)
		if err != nil {
			return fmt.Errorf("error parsing command %s: %w", flagForceCommand, err)
		}
	}

	var authorizedKeys []ssh.PublicKey
	if flagAuthorizedKeys != "" {
		authorizedKeys, err = host.AuthorizedKeys(flagAuthorizedKeys)
	}
	if err != nil {
		return fmt.Errorf("error reading authorized keys: %w", err)
	}
	if flagGitHubUsers != nil {
		gitHubUserKeys, err := host.GitHubUserKeys(flagGitHubUsers)
		if err != nil {
			return fmt.Errorf("error reading GitHub user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, gitHubUserKeys...)
	}
	if flagGitLabUsers != nil {
		gitLabUserKeys, err := host.GitLabUserKeys(flagGitLabUsers)
		if err != nil {
			return fmt.Errorf("error reading GitLab user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, gitLabUserKeys...)
	}

	if !filepath.IsAbs(flagVSCodeDir) {
		return fmt.Errorf("only support absolute path in vscode, but get: %s", flagVSCodeDir)
	}

	if _, err := os.Stat(flagVSCodeDir); err != nil {
		return fmt.Errorf("error reading vscode dir: %w", err)
	}

	if flagVSCode && flagReadOnly {
		return fmt.Errorf("can't mix --vscode with --read-only")
	}

	signers, cleanup, err := host.Signers(flagPrivateKeys)
	if err != nil {
		return fmt.Errorf("error reading private keys: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	hkcb, err := host.NewPromptingHostKeyCallback(os.Stdin, os.Stdout, flagKnownHostsFilename)
	if err != nil {
		return err
	}

	lf, err := utils.OpenHostLogFile()
	if err != nil {
		return err
	}
	defer lf.Close()

	logger := log.New()
	logger.SetOutput(lf)

	h := &host.Host{
		Host:                   flagServer,
		Command:                args,
		ForceCommand:           forceCommand,
		Signers:                signers,
		HostKeyCallback:        hkcb,
		AuthorizedKeys:         authorizedKeys,
		KeepAliveDuration:      50 * time.Second, // nlb is 350 sec & heroku router is 55 sec
		SessionCreatedCallback: displaySessionCallback,
		ClientJoinedCallback:   clientJoinedCallback,
		ClientLeftCallback:     clientLeftCallback,
		Stdin:                  os.Stdin,
		Stdout:                 os.Stdout,
		Logger:                 logger,
		ReadOnly:               flagReadOnly,
		VSCode:                 flagVSCode,
	}

	return h.Run(context.Background())
}

func clientJoinedCallback(c *api.Client) {
	_ = beeep.Notify("Upterm Client Joined", notifyBody(c), "")
}

func clientLeftCallback(c *api.Client) {
	_ = beeep.Notify("Upterm Client Left", notifyBody(c), "")
}

func notifyBody(c *api.Client) string {
	return clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint)
}

func displaySessionCallback(session *api.GetSessionResponse) error {
	if err := displaySession(session); err != nil {
		return err
	}

	return nil
}

func defaultPrivateKeys(homeDir string) []string {
	var pks []string
	for _, f := range []string{
		"id_ed25519",
		"id_ed25519_sk",
		"id_ecdsa",
		"id_ecdsa_sk",
		"id_dsa",
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

func defaultKnownHost(homeDir string) string {
	return filepath.Join(homeDir, ".ssh", "known_hosts")
}
