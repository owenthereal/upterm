package utils

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/dchest/uniuri"
	"golang.org/x/crypto/ssh"
)

const (
	logFile = "upterm.log"
)

func UptermDir() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homedir, ".upterm"), nil
}

func CreateUptermDir() (string, error) {
	dir, err := UptermDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	return dir, nil
}

func OpenHostLogFile() (*os.File, error) {
	dir, err := CreateUptermDir()
	if err != nil {
		return nil, err
	}

	return os.OpenFile(filepath.Join(dir, logFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
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

// If version1 < version2, return -1.
// If version1 > version2, return 1.
// Otherwise, return 0.
// https://leetcode.com/problems/compare-version-numbers/
func CompareVersion(version1 string, version2 string) int {
	len1, len2, i, j := len(version1), len(version2), 0, 0
	for i < len1 || j < len2 {
		n1 := 0
		for i < len1 && '0' <= version1[i] && version1[i] <= '9' {
			n1 = n1*10 + int(version1[i]-'0')
			i++
		}
		n2 := 0
		for j < len2 && '0' <= version2[j] && version2[j] <= '9' {
			n2 = n2*10 + int(version2[j]-'0')
			j++
		}
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
		i, j = i+1, j+1
	}
	return 0
}

func ParseURL(str string) (u *url.URL, scheme string, host string, port string, err error) {
	u, err = url.Parse(str)
	if err != nil {
		return
	}

	scheme = u.Scheme
	host, port, err = net.SplitHostPort(u.Host)
	if err != nil {
		if !strings.Contains(err.Error(), "missing port in address") {
			return
		}

		err = nil
		host = u.Host
		switch u.Scheme {
		case "ssh":
			port = "22"
		case "ws":
			port = "80"
		case "wss":
			port = "443"
		}
	}

	return
}
