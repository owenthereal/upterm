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

func AuthMethods(privateKeys []string) (auths []ssh.AuthMethod, cleanup func(), err error) {
	cleanup = func() {}

	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		auths, err = AuthMethodsFromFiles(privateKeys)
	} else {
		auths, cleanup, err = AuthMethodsFromSSHAgent(socket, privateKeys)
	}

	return auths, cleanup, err
}

func AuthMethodsFromFiles(privateKeys []string) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod
	for _, file := range privateKeys {
		s, err := signerFromFile(file)
		if err == nil {
			auths = append(auths, ssh.PublicKeys(s))
		}
	}

	return auths, nil
}

func AuthMethodsFromSSHAgent(socket string, privateKeys []string) (auths []ssh.AuthMethod, cancel func(), err error) {
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
		auths, err = AuthMethodsFromFiles(privateKeys)
		if err != nil {
			return nil, cancel, err
		}
	} else {
		auths = append(auths, ssh.PublicKeysCallback(agentClient.Signers))
	}

	return auths, cancel, nil
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
