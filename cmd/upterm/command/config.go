package command

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func configCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage upterm configuration",
		Long: fmt.Sprintf(`Manage upterm configuration file.

Config file: %s

This follows the XDG Base Directory Specification.

Configuration priority (highest to lowest):
  1. Command-line flags
  2. Environment variables (UPTERM_ prefix)
  3. Config file
  4. Default values`, configPath),
	}

	cmd.AddCommand(configPathCmd())
	cmd.AddCommand(configViewCmd())
	cmd.AddCommand(configEditCmd())

	return cmd
}

func configPathCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Show the path to the config file",
		Long: fmt.Sprintf(`Show the path to the config file.

Config file: %s

The config file is optional and created manually by users.`, configPath),
		Example: `  # Show config file path:
  upterm config path

  # Create config file directory:
  mkdir -p "$(dirname "$(upterm config path)")"`,
		RunE: configPathRunE,
	}

	return cmd
}

func configViewCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "view",
		Short: "View the config file contents",
		Long: fmt.Sprintf(`View the config file contents.

Config file: %s

If the config file exists, this command displays its contents. If it doesn't
exist, this command shows an example config file that you can use as a template.`, configPath),
		Example: `  # View current config:
  upterm config view

  # View and save as new config:
  upterm config view > "$(upterm config path)"`,
		RunE: configViewRunE,
	}

	return cmd
}

func configEditCmd() *cobra.Command {
	configPath := utils.UptermConfigFilePath()
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit the config file",
		Long: fmt.Sprintf(`Edit the config file in your default editor.

Config file: %s

This command opens the config file in your editor (determined by $VISUAL, $EDITOR,
or a sensible default). If the config file doesn't exist, it creates a template
with example settings and comments.

The config directory is created automatically if it doesn't exist.`, configPath),
		Example: `  # Edit config file:
  upterm config edit

  # Use a specific editor:
  EDITOR=nano upterm config edit`,
		RunE: configEditRunE,
	}

	return cmd
}

func configPathRunE(c *cobra.Command, args []string) error {
	configPath := utils.UptermConfigFilePath()
	fmt.Println(configPath)
	return nil
}

func configViewRunE(c *cobra.Command, args []string) error {
	configPath := utils.UptermConfigFilePath()

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Show example config
		fmt.Println("# Config file does not exist. Example config:")
		fmt.Println()
		fmt.Print(exampleConfig())
		return nil
	}

	// Read and display file
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	fmt.Print(string(content))
	return nil
}

func configEditRunE(c *cobra.Command, args []string) error {
	configPath := utils.UptermConfigFilePath()
	configDir := utils.UptermConfigDir()

	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create example config if file doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.WriteFile(configPath, []byte(exampleConfig()), 0600); err != nil {
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	// Determine editor to use
	editor := getEditor()

	// Open editor
	cmd := exec.Command(editor, configPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to open editor: %w", err)
	}

	// Validate config after editing
	if err := validateConfig(configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: config file has syntax errors: %v\n", err)
		fmt.Fprintf(os.Stderr, "Edit again with 'upterm config edit' or view with 'upterm config view'.\n")
	}

	return nil
}

// getEditor returns the editor to use, checking $VISUAL, $EDITOR, then defaults.
func getEditor() string {
	// Check $VISUAL first (for full-screen editors)
	if editor := os.Getenv("VISUAL"); editor != "" {
		return editor
	}

	// Check $EDITOR (for line editors)
	if editor := os.Getenv("EDITOR"); editor != "" {
		return editor
	}

	// Platform-specific defaults
	switch runtime.GOOS {
	case "windows":
		return "notepad"
	default:
		// Unix-like systems: prefer nano for better UX, fall back to vi
		if _, err := exec.LookPath("nano"); err == nil {
			return "nano"
		}
		return "vi"
	}
}

// validateConfig validates the config file by attempting to parse it.
func validateConfig(path string) error {
	v := viper.New()
	v.SetConfigFile(path)
	return v.ReadInConfig()
}

// exampleConfig returns an example config file with comments.
func exampleConfig() string {
	return `# Upterm Configuration File
#
# This file follows the XDG Base Directory Specification.
# Settings here are overridden by environment variables (UPTERM_*) and command-line flags.
#
# Configuration priority (highest to lowest):
#   1. Command-line flags
#   2. Environment variables (UPTERM_* prefix)
#   3. This config file
#   4. Default values

# Debug logging (default: false)
# When enabled, writes debug-level logs to the log file.
# debug: true

# Default server address for hosting sessions (default: ssh://uptermd.upterm.dev:22)
# Supported protocols: ssh, ws, wss
# server: ssh://uptermd.upterm.dev:22

# Force a specific command for clients (default: none)
# When set, clients cannot run arbitrary commands.
# Use YAML array syntax: ["command", "arg1", "arg2"]
# force-command: ["/bin/bash", "-l"]

# Path to authorized_keys file for client authentication (default: none)
# authorized-keys: /path/to/authorized_keys

# Paths to private key files (default: generates ephemeral key)
# private-key:
#   - /path/to/private/key1
#   - /path/to/private/key2

# Read-only mode (default: false)
# When enabled, clients can view but not interact with the session.
# read-only: false

# Auto-accept clients without confirmation (default: false)
# WARNING: Only use this in trusted environments.
# accept: false

# Hide client IP addresses from logs and display (default: false)
# hide-client-ip: false
`
}
