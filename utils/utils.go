package utils

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jingweno/upterm/upterm"
	"golang.org/x/crypto/ssh"
)

func WebSocketDialHeader(user, pass string, isClient bool) http.Header {
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	header := make(http.Header)
	header.Add("Authorization", "Basic "+auth)

	ver := upterm.HostSSHClientVersion
	if isClient {
		ver = upterm.ClientSSHClientVersion
	}
	header.Add("Upterm-Client-Version", ver)

	return header
}

func UptermDir() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homedir, ".upterm"), nil
}

func DefaultLocalhost(defaultPort string) string {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	return fmt.Sprintf("127.0.0.1:%s", port)
}

func CreateSignersFromFiles(paths []string) ([]ssh.Signer, error) {
	files, err := readFiles(paths)
	if err != nil {
		return nil, err
	}

	return CreateSigners(files)
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
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}

		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			return nil, err
		}

		signers = append(signers, signer)
	}

	return signers, nil
}

func readFiles(paths []string) ([][]byte, error) {
	var files [][]byte

	for _, p := range paths {
		b, err := ioutil.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", p, err)
		}

		files = append(files, b)
	}

	return files, nil
}
