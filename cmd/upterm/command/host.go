package command

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/eiannone/keyboard"
	"github.com/gen2brain/beeep"
	"github.com/google/shlex"
	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	flagServer             string
	flagForceCommand       string
	flagPrivateKeys        []string
	flagKnownHostsFilename string
	flagAuthorizedKeys     string
	flagGitHubUsers        []string
	flagGitLabUsers        []string
	flagSourceHutUsers     []string
	flagReadOnly           bool
	flagAccept             bool
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Host a terminal session",
		Long: `Host a terminal session via a reverse SSH tunnel to the Upterm server, linking the IO of the host
and client to a command's IO. Authentication against the Upterm server defaults to using private key files located
at ~/.ssh/id_dsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ed25519, and ~/.ssh/id_rsa. If no private key file is found, it resorts
to reading private keys from the SSH Agent. Absence of private keys in files or SSH Agent generates an on-the-fly
private key. To authorize client connections, specify a authorized_key file with public keys using --authorized-keys.`,
		Example: `  # Host a terminal session running $SHELL, attaching client's IO to the host's:
  upterm host

  # Accept client connections automatically without prompts:
  upterm host --accept

  # Host a terminal session allowing only specified public key(s) to connect:
  upterm host --authorized-keys PATH_TO_AUTHORIZED_KEY_FILE

  # Host a session executing a custom command:
  upterm host -- docker run --rm -ti ubuntu bash

  # Host a 'tmux new -t pair-programming' session, forcing clients to join with 'tmux attach -t pair-programming':
  upterm host --force-command 'tmux attach -t pair-programming' -- tmux new -t pair-programming

  # Use a different Uptermd server, hosting a session via WebSocket:
  upterm host --server wss://YOUR_UPTERMD_SERVER -- YOUR_COMMAND`,
		PreRunE: validateShareRequiredFlags,
		RunE:    shareRunE,
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	cmd.PersistentFlags().StringVarP(&flagServer, "server", "", "ssh://uptermd.upterm.dev:22", "Specify the upterm server address (required). Supported protocols: ssh, ws, wss.")
	cmd.PersistentFlags().StringVarP(&flagForceCommand, "force-command", "f", "", "Enforce a specified command for clients to join, and link the command's input/output to the client's terminal.")
	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "Specify private key files for public key authentication with the upterm server (required).")
	cmd.PersistentFlags().StringVarP(&flagKnownHostsFilename, "known-hosts", "", defaultKnownHost(homeDir), "Specify a file containing known keys for remote hosts (required).")
	cmd.PersistentFlags().StringVar(&flagAuthorizedKeys, "authorized-keys", "", "Specify a authorize_keys file listing authorized public keys for connection.")
	cmd.PersistentFlags().StringSliceVar(&flagGitHubUsers, "github-user", nil, "Authorize specified GitHub users by allowing their public keys to connect. Configure GitHub CLI environment variables as needed; see https://cli.github.com/manual/gh_help_environment for details.")
	cmd.PersistentFlags().StringSliceVar(&flagGitLabUsers, "gitlab-user", nil, "Authorize specified GitLab users by allowing their public keys to connect.")
	cmd.PersistentFlags().StringSliceVar(&flagSourceHutUsers, "srht-user", nil, "Authorize specified SourceHut users by allowing their public keys to connect.")
	cmd.PersistentFlags().BoolVar(&flagAccept, "accept", false, "Automatically accept client connections without prompts.")
	cmd.PersistentFlags().BoolVarP(&flagReadOnly, "read-only", "r", false, "Host a read-only session, preventing client interaction.")

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

	lf, err := utils.OpenHostLogFile()
	if err != nil {
		return err
	}
	defer lf.Close()

	logger := log.New()
	logger.SetOutput(lf)

	var authorizedKeys []*host.AuthorizedKey
	var restrictedAccess bool
	if flagAuthorizedKeys != "" {
		restrictedAccess = true
		aks, err := host.AuthorizedKeysFromFile(flagAuthorizedKeys)
		if err != nil {
			return fmt.Errorf("error reading authorized keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, aks)
	}
	if flagGitHubUsers != nil {
		restrictedAccess = true
		gitHubUserKeys, err := host.GitHubUserAuthorizedKeys(flagGitHubUsers, logger)
		if err != nil {
			return fmt.Errorf("error reading GitHub user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, gitHubUserKeys...)
	}
	if flagGitLabUsers != nil {
		restrictedAccess = true
		gitLabUserKeys, err := host.GitLabUserAuthorizedKeys(flagGitLabUsers)
		if err != nil {
			return fmt.Errorf("error reading GitLab user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, gitLabUserKeys...)
	}
	if flagSourceHutUsers != nil {
		restrictedAccess = true
		sourceHutUserKeys, err := host.SourceHutUserAuthorizedKeys(flagSourceHutUsers)
		if err != nil {
			return fmt.Errorf("error reading SourceHut user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, sourceHutUserKeys...)
	}

	if len(authorizedKeys) == 0 && restrictedAccess {
		return fmt.Errorf("no authorized keys found")
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

	if !flagAccept {
		fmt.Printf("\nRun 'upterm session current' to display this screen again\n\n")

		if err := keyboard.Open(); err != nil {
			return err
		}
		defer keyboard.Close()

		fmt.Println("Press <q> or <ctrl-c> to accept connections...")
		for {
			char, key, err := keyboard.GetKey()
			if err != nil {
				return err
			} else if key == keyboard.KeyCtrlC || char == 'q' {
				break
			}
		}
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
