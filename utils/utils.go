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

// UptermRuntimeDir returns the directory for runtime files (sockets).
//
// Following the XDG Base Directory Specification, this directory maps to
// XDG_RUNTIME_DIR/upterm and is typically cleaned on logout/reboot.
//
// Platform-specific paths:
//   - Linux:   /run/user/1000/upterm
//   - macOS:   $TMPDIR/upterm (e.g., /var/folders/.../T/upterm)
//   - Windows: %LOCALAPPDATA%\Temp\upterm
func UptermRuntimeDir() string {
	return filepath.Join(xdg.RuntimeDir, appName)
}

// UptermStateDir returns the directory for state files (logs).
//
// Following the XDG Base Directory Specification, this directory maps to
// XDG_STATE_HOME/upterm and persists across sessions.
//
// Platform-specific paths:
//   - Linux:   ~/.local/state/upterm
//   - macOS:   ~/Library/Application Support/upterm
//   - Windows: %LOCALAPPDATA%\upterm
func UptermStateDir() string {
	return filepath.Join(xdg.StateHome, appName)
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
// Platform-specific paths:
//   - Linux:   ~/.config/upterm
//   - macOS:   ~/Library/Application Support/upterm
//   - Windows: %LOCALAPPDATA%\upterm
func UptermConfigDir() string {
	return filepath.Join(xdg.ConfigHome, appName)
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
