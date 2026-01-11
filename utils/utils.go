package utils

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	gssh "github.com/charmbracelet/ssh"
	"github.com/dchest/uniuri"
	"golang.org/x/crypto/ssh"
)

const (
	logFile    = "upterm.log"
	configFile = "config.yaml"
	appName    = "upterm"
)

// envGetter is a function type for getting environment variables.
// This allows for dependency injection in tests.
type envGetter func(string) string

// xdgDirWithFallbackEnv returns an XDG directory path with fallback to HOME-based directory.
// It follows this priority:
//  1. If envVar is explicitly set, use it (trust user configuration)
//  2. If xdgPath exists and is accessible, use it
//  3. Fall back to $HOME/.upterm
//  4. Final fallback to os.TempDir()/.upterm (if HOME unavailable)
//
// This handles cases where XDG defaults point to system directories that may not exist
// or be writable in non-interactive environments (e.g., /run/user/<uid> in CI/containers).
//
// The getenv parameter allows for dependency injection in tests.
func xdgDirWithFallbackEnv(envVar, xdgPath string, getenv envGetter) string {
	// If user explicitly set the XDG env var, respect it unconditionally
	// Use the actual env var value, not the xdg library's cached value
	if envValue := getenv(envVar); envValue != "" {
		return filepath.Join(envValue, appName)
	}

	// Check if the XDG default path exists before creating the appName subdirectory within it
	if _, err := os.Stat(xdgPath); err == nil {
		return filepath.Join(xdgPath, appName)
	}

	// Fall back to home directory structure
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = xdg.Home // Try xdg library's cached value
	}

	// Final fallback: use temp directory if home is unavailable
	if home == "" {
		home = os.TempDir()
	}

	return filepath.Join(home, "."+appName)
}

// xdgDirWithFallback returns an XDG directory path with fallback to HOME-based directory.
// This is a convenience wrapper around xdgDirWithFallbackEnv that uses os.Getenv.
func xdgDirWithFallback(envVar, xdgPath string) string {
	return xdgDirWithFallbackEnv(envVar, xdgPath, os.Getenv)
}

// UptermRuntimeDir returns the directory for runtime files (sockets).
//
// Following the XDG Base Directory Specification, this directory maps to
// XDG_RUNTIME_DIR/upterm when available and is typically cleaned on logout/reboot.
//
// Directory selection priority:
//  1. $XDG_RUNTIME_DIR/upterm (if XDG_RUNTIME_DIR is explicitly set)
//  2. Platform default if accessible:
//     - Linux:   /run/user/1000/upterm (requires login session)
//     - macOS:   $TMPDIR/upterm (e.g., /var/folders/.../T/upterm)
//     - Windows: %LOCALAPPDATA%\upterm
//  3. Fallback: $HOME/.upterm (for non-interactive environments)
//  4. Final fallback: os.TempDir()/.upterm (if HOME unavailable)
func UptermRuntimeDir() string {
	return xdgDirWithFallback("XDG_RUNTIME_DIR", xdg.RuntimeDir)
}

// UptermStateDir returns the directory for state files (logs).
//
// Following the XDG Base Directory Specification, this directory maps to
// XDG_STATE_HOME/upterm and persists across sessions.
//
// Directory selection priority:
//  1. $XDG_STATE_HOME/upterm (if XDG_STATE_HOME is explicitly set)
//  2. Platform default if accessible:
//     - Linux:   ~/.local/state/upterm
//     - macOS:   ~/Library/Application Support/upterm
//     - Windows: %LOCALAPPDATA%\upterm
//  3. Fallback: $HOME/.upterm
//  4. Final fallback: os.TempDir()/.upterm (if HOME unavailable)
func UptermStateDir() string {
	return xdgDirWithFallback("XDG_STATE_HOME", xdg.StateHome)
}

// UptermLogFilePath returns the path to the log file in the state directory.
//
// Following the XDG Base Directory Specification, this file is stored in
// XDG_STATE_HOME/upterm and persists across sessions.
//
// Platform-specific paths:
//   - Linux:   ~/.local/state/upterm/upterm.log
//   - macOS:   ~/Library/Application Support/upterm/upterm.log
//   - Windows: %LOCALAPPDATA%\upterm\upterm.log
//
// Note: The directory is created lazily by the logging system when the file is opened.
func UptermLogFilePath() string {
	return filepath.Join(UptermStateDir(), logFile)
}

// UptermConfigDir returns the directory for configuration files.
//
// Following the XDG Base Directory Specification, this directory maps to
// XDG_CONFIG_HOME/upterm and persists across sessions.
//
// Directory selection priority:
//  1. $XDG_CONFIG_HOME/upterm (if XDG_CONFIG_HOME is explicitly set)
//  2. Platform default if accessible:
//     - Linux:   ~/.config/upterm
//     - macOS:   ~/Library/Application Support/upterm
//     - Windows: %LOCALAPPDATA%\upterm
//  3. Fallback: $HOME/.upterm
//  4. Final fallback: os.TempDir()/.upterm (if HOME unavailable)
func UptermConfigDir() string {
	return xdgDirWithFallback("XDG_CONFIG_HOME", xdg.ConfigHome)
}

// UptermConfigFilePath returns the path to the config file.
//
// Following the XDG Base Directory Specification, this file is stored in
// XDG_CONFIG_HOME/upterm and persists across sessions.
//
// Platform-specific paths:
//   - Linux:   ~/.config/upterm/config.yaml
//   - macOS:   ~/Library/Application Support/upterm/config.yaml
//   - Windows: %LOCALAPPDATA%\upterm\config.yaml
//
// Note: The config file is optional and created manually by users.
func UptermConfigFilePath() string {
	return filepath.Join(UptermConfigDir(), configFile)
}

// CreateUptermRuntimeDir creates the runtime directory for sockets.
// Mode 0700 ensures only the current user can access sockets.
func CreateUptermRuntimeDir() (string, error) {
	dir := UptermRuntimeDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func DefaultLocalhost(defaultPort string) string {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	return fmt.Sprintf("127.0.0.1:%s", port)
}

func CreateSigners(privateKeys [][]byte) ([]ssh.Signer, error) {
	var signers []ssh.Signer

	for _, pk := range privateKeys {
		signer, err := ssh.ParsePrivateKey(pk)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	// generate one if no signer
	if len(signers) == 0 {
		_, epk, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		signer, err := ssh.NewSignerFromKey(epk)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)

	}

	return signers, nil
}

func ReadFiles(paths []string) ([][]byte, error) {
	var files [][]byte

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", p, err)
		}

		files = append(files, b)
	}

	return files, nil
}

func GenerateSessionID() string {
	return uniuri.NewLen(uniuri.UUIDLen)
}

func FingerprintSHA256(key ssh.PublicKey) string {
	hash := sha256.Sum256(key.Marshal())
	b64hash := base64.StdEncoding.EncodeToString(hash[:])
	return fmt.Sprintf("SHA256:%s", strings.TrimRight(b64hash, "="))
}

func KeysEqual(pk1 ssh.PublicKey, pk2 ssh.PublicKey) bool {
	return gssh.KeysEqual(publicKey(pk1), publicKey(pk2))
}

func publicKey(pk ssh.PublicKey) ssh.PublicKey {
	cert, ok := pk.(*ssh.Certificate)
	if ok {
		pk = cert.Key
	}

	return pk
}

// ShortenHomePath replaces the home directory prefix with ~ for cleaner display.
// If the path doesn't start with home directory, it's returned unchanged.
func ShortenHomePath(path string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return path
	}
	if after, found := strings.CutPrefix(path, homeDir); found {
		return "~" + after
	}
	return path
}
