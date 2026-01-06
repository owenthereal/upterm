package command

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/gen2brain/beeep"
	"github.com/google/shlex"
	"github.com/hashicorp/go-multierror"
	"github.com/owenthereal/upterm/cmd/upterm/command/internal/tui"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/icon"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// UserDiscardedError represents a user's intentional choice to discard the session
type UserDiscardedError struct{}

func (e UserDiscardedError) Error() string {
	return "session discarded by user"
}

// UserInterruptedError represents a user's Ctrl+C interruption
type UserInterruptedError struct{}

func (e UserInterruptedError) Error() string {
	return "interrupted by user"
}

var (
	flagServer             string
	flagForceCommand       string
	flagPrivateKeys        []string
	flagKnownHostsFilename string
	flagAuthorizedKeys     string
	flagCodebergUsers      []string
	flagGitHubUsers        []string
	flagGitLabUsers        []string
	flagSourceHutUsers     []string
	flagReadOnly           bool
	flagAccept             bool
	flagSkipHostKeyCheck   bool
)

func hostCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Host a terminal session",
		Long: `Host a terminal session via a reverse SSH tunnel to the Upterm server.

The session links the host and client IO to a command's IO. Authentication with the
Upterm server uses private keys in this order:
  1. Private key files: ~/.ssh/id_dsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ed25519, ~/.ssh/id_rsa
  2. SSH Agent keys
  3. Auto-generated ephemeral key (if no keys found)

To authorize client connections, use --authorized-keys to specify an authorized_keys file
containing client public keys.`,
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
		slog.Error("error getting user home directory", "error", err)
		os.Exit(1)
	}

	cmd.PersistentFlags().StringVarP(&flagServer, "server", "", "ssh://uptermd.upterm.dev:22", "Specify the upterm server address (required). Supported protocols: ssh, ws, wss.")
	cmd.PersistentFlags().StringVarP(&flagForceCommand, "force-command", "f", "", "Enforce a specified command for clients to join, and link the command's input/output to the client's terminal.")
	cmd.PersistentFlags().StringSliceVarP(&flagPrivateKeys, "private-key", "i", defaultPrivateKeys(homeDir), "Specify private key files for public key authentication with the upterm server (required).")
	cmd.PersistentFlags().StringVarP(&flagKnownHostsFilename, "known-hosts", "", defaultKnownHost(homeDir), "Specify a file containing known keys for remote hosts (required).")
	cmd.PersistentFlags().StringVar(&flagAuthorizedKeys, "authorized-keys", "", "Specify a authorize_keys file listing authorized public keys for connection.")
	cmd.PersistentFlags().StringSliceVar(&flagCodebergUsers, "codeberg-user", nil, "Authorize specified Codeberg users by allowing their public keys to connect.")
	cmd.PersistentFlags().StringSliceVar(&flagGitHubUsers, "github-user", nil, "Authorize specified GitHub users by allowing their public keys to connect. Configure GitHub CLI environment variables as needed; see https://cli.github.com/manual/gh_help_environment for details.")
	cmd.PersistentFlags().StringSliceVar(&flagGitLabUsers, "gitlab-user", nil, "Authorize specified GitLab users by allowing their public keys to connect.")
	cmd.PersistentFlags().StringSliceVar(&flagSourceHutUsers, "srht-user", nil, "Authorize specified SourceHut users by allowing their public keys to connect.")
	cmd.PersistentFlags().BoolVar(&flagAccept, "accept", false, "Automatically accept client connections without prompts.")
	cmd.PersistentFlags().BoolVarP(&flagReadOnly, "read-only", "r", false, "Host a read-only session, preventing client interaction.")
	cmd.PersistentFlags().BoolVar(&flagHideClientIP, "hide-client-ip", false, "Hide client IP addresses from output (auto-enabled in CI environments).")
	cmd.PersistentFlags().BoolVar(&flagSkipHostKeyCheck, "skip-host-key-check", false, "Automatically accept unknown server host keys and add them to known_hosts (similar to SSH's StrictHostKeyChecking=accept-new). This bypasses host key verification for new connections.")

	return cmd
}

func validateShareRequiredFlags(c *cobra.Command, args []string) error {
	var result error

	if flagServer == "" {
		result = multierror.Append(result, fmt.Errorf("missing flag --server"))
	} else {
		u, err := url.Parse(flagServer)
		if err != nil {
			result = multierror.Append(result, fmt.Errorf("error parsing server URL: %w", err))
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
		shellCmd := getDefaultShell()
		args, err = shlex.Split(shellCmd)
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

	logger := uptermctx.Logger(c.Context())
	if logger == nil {
		return fmt.Errorf("logger not available")
	}

	var authorizedKeys []*host.AuthorizedKey
	if flagAuthorizedKeys != "" {
		aks, err := host.AuthorizedKeysFromFile(flagAuthorizedKeys)
		if err != nil {
			return fmt.Errorf("error reading authorized keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, aks)
	}
	if flagCodebergUsers != nil {
		codebergUserKeys, err := host.CodebergUserAuthorizedKeys(flagCodebergUsers)
		if err != nil {
			return fmt.Errorf("error reading Codeberg user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, codebergUserKeys...)
	}
	if flagGitHubUsers != nil {
		gitHubUserKeys, err := host.GitHubUserAuthorizedKeys(flagGitHubUsers, logger.Logger)
		if err != nil {
			return fmt.Errorf("error reading GitHub user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, gitHubUserKeys...)
	}
	if flagGitLabUsers != nil {
		gitLabUserKeys, err := host.GitLabUserAuthorizedKeys(flagGitLabUsers)
		if err != nil {
			return fmt.Errorf("error reading GitLab user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, gitLabUserKeys...)
	}
	if flagSourceHutUsers != nil {
		sourceHutUserKeys, err := host.SourceHutUserAuthorizedKeys(flagSourceHutUsers)
		if err != nil {
			return fmt.Errorf("error reading SourceHut user keys: %w", err)
		}
		authorizedKeys = append(authorizedKeys, sourceHutUserKeys...)
	}

	signers, cleanup, err := host.Signers(flagPrivateKeys)
	if err != nil {
		return fmt.Errorf("error reading private keys: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	var hkcb ssh.HostKeyCallback
	if flagSkipHostKeyCheck {
		hkcb, err = host.NewAutoAcceptingHostKeyCallback(os.Stdout, flagKnownHostsFilename)
	} else {
		hkcb, err = host.NewPromptingHostKeyCallback(os.Stdin, os.Stdout, flagKnownHostsFilename)
	}
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
		Logger:                 logger.Logger,
		ReadOnly:               flagReadOnly,
	}

	err = h.Run(c.Context())

	// Handle user actions specially - no help menu
	var userDiscardedErr UserDiscardedError
	if errors.As(err, &userDiscardedErr) {
		return nil // Clean exit for user discard (exit code 0)
	}

	var userInterruptedErr UserInterruptedError
	if errors.As(err, &userInterruptedErr) {
		// Set both flags to prevent help menu and error display
		c.SilenceUsage = true
		c.SilenceErrors = true
		return userInterruptedErr
	}

	return err
}

func clientJoinedCallback(c *api.Client) {
	_ = beeep.Notify("Upterm Client Joined", notifyBody(c), icon.Upterm)
}

func clientLeftCallback(c *api.Client) {
	_ = beeep.Notify("Upterm Client Left", notifyBody(c), icon.Upterm)
}

func notifyBody(c *api.Client) string {
	return clientDesc(c.Addr, c.Version, c.PublicKeyFingerprint)
}

func displaySessionCallback(ctx context.Context, session *api.GetSessionResponse) error {
	// Build session detail
	detail, err := buildSessionDetail(session)
	if err != nil {
		return fmt.Errorf("failed to build session detail: %w", err)
	}

	// Create and run the integrated TUI model (session display + confirmation)
	model := tui.NewHostSessionModel(detail, flagAccept)
	p := tea.NewProgram(model, tea.WithContext(ctx))

	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("session confirmation failed: %w", err)
	}

	// Extract result from the model
	sessionModel, ok := finalModel.(tui.HostSessionModel)
	if !ok {
		return fmt.Errorf("unexpected model type: got %T, want tui.HostSessionModel", finalModel)
	}

	// Handle the result
	switch sessionModel.Result() {
	case tui.HostSessionConfirmAccepted:
		return nil
	case tui.HostSessionConfirmRejected:
		return UserDiscardedError{}
	case tui.HostSessionConfirmInterrupted:
		return UserInterruptedError{}
	default:
		return fmt.Errorf("unknown confirmation result: %d", sessionModel.Result())
	}
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
