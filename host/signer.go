package host

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	errCanNotDecodeEncryptedPrivateKeys = "cannot decode encrypted private keys"
	errDecryptionPasswordIncorrect      = "decryption password incorrect"
)

func AuthorizedKeys(file string) ([]ssh.PublicKey, error) {
	authorizedKeysBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil
	}

	var authorizedKeys []ssh.PublicKey
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeys = append(authorizedKeys, pubKey)
		authorizedKeysBytes = rest
	}

	return authorizedKeys, nil
}

func Signers(privateKeys []string) (signers []ssh.Signer, cleanup func(), err error) {
	cleanup = func() {}

	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		signers, err = SignersFromFiles(privateKeys)
	} else {
		signers, cleanup, err = SignersFromSSHAgent(socket, privateKeys)
	}

	return signers, cleanup, err
}

func SignersFromFiles(privateKeys []string) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, file := range privateKeys {
		s, err := signerFromFile(file)
		if err == nil {
			signers = append(signers, s)
		}
	}

	return signers, nil
}

func SignersFromSSHAgent(socket string, privateKeys []string) (signers []ssh.Signer, cancel func(), err error) {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to ssh-agent %s: %w", socket, err)
	}
	cancel = func() { conn.Close() }

	agentClient := agent.NewClient(conn)
	keys, err := agentClient.List()
	if err != nil {
		return nil, cancel, err
	}

	// fallback to read from files if ssh-agent doesn't match number of keys
	if len(keys) != len(privateKeys) {
		signers, err = SignersFromFiles(privateKeys)
		if err != nil {
			return nil, cancel, err
		}
	} else {
		signers, err = agentClient.Signers()
		if err != nil {
			return signers, cancel, err
		}
	}

	return signers, cancel, nil
}

func signerFromFile(file string) (ssh.Signer, error) {
	pb, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	s, err := ssh.ParsePrivateKey(pb)
	if err == nil {
		return s, err
	}
	if !strings.Contains(err.Error(), errCanNotDecodeEncryptedPrivateKeys) {
		return nil, err
	}

	// simulate ssh to retry 3 times
	for i := 0; i < 3; i++ {
		pass, err := promptForPassphrase(file)

		s, err := ssh.ParsePrivateKeyWithPassphrase(pb, bytes.TrimSpace(pass))
		if err == nil {
			return s, err
		}

		if !strings.Contains(err.Error(), errDecryptionPasswordIncorrect) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("error decrypting private key %s", file)
}

func promptForPassphrase(file string) ([]byte, error) {
	defer fmt.Println("") // clear return

	fmt.Printf("Enter passphrase for key '%s': ", file)

	return terminal.ReadPassword(int(syscall.Stdin))
}
