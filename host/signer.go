package host

import (
	"bytes"
	"crypto/x509"
	"errors"
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
	errCannotDecodeEncryptedPrivateKeys = "cannot decode encrypted private keys"
)

type errDescryptingPrivateKey struct {
	file string
}

func (e *errDescryptingPrivateKey) Error() string {
	return fmt.Sprintf("error decrypting private key %s", e.file)
}

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

func Signers(privateKeys []string) ([]ssh.Signer, func(), error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	cleanup := func() {}

	if socket == "" {
		signers, err := SignersFromFiles(privateKeys)
		return signers, cleanup, err
	}

	signers, cleanup, err := SignersFromSSHAgent(socket, privateKeys)
	if err != nil {
		signers, err = SignersFromFiles(privateKeys)
		return signers, cleanup, err
	}

	return signers, cleanup, nil
}

func SignersFromFiles(privateKeys []string) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, file := range privateKeys {
		s, err := signerFromFile(file, promptForPassphrase)
		if err == nil {
			signers = append(signers, s)
		}
	}

	return signers, nil
}

func SignersFromSSHAgent(socket string, privateKeys []string) ([]ssh.Signer, func(), error) {
	cleanup := func() {}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, cleanup, err
	}

	cleanup = func() { conn.Close() }
	signers, err := signersFromSSHAgent(agent.NewClient(conn), privateKeys, promptForPassphrase)

	return signers, cleanup, err
}

func signersFromSSHAgent(client agent.Agent, privateKeys []string, promptForPassphrase func(file string) ([]byte, error)) ([]ssh.Signer, error) {
	keys, err := client.List()
	if err != nil {
		return nil, err
	}
	publicKeys := readPublicKeysBestEfforts(privateKeys)

	var agentKeysIdx []int
	for i, key := range keys {
		for _, pk := range publicKeys {
			if bytes.Equal(key.Blob, pk.Marshal()) {
				agentKeysIdx = append(agentKeysIdx, i)
			}
		}
	}

	if len(agentKeysIdx) > 0 {
		signers, err := client.Signers()
		if err != nil {
			return nil, err
		}

		var matchedSigners []ssh.Signer
		for _, idx := range agentKeysIdx {
			matchedSigners = append(matchedSigners, signers[idx])
		}

		if len(matchedSigners) == 0 {
			return nil, fmt.Errorf("No matching signers from SSH agent")
		}

		return matchedSigners, nil
	}

	// Add key if there is no match keys
	if err := addPrivateKeysToAgent(client, privateKeys, promptForPassphrase); err != nil {
		return nil, err
	}

	return signersFromSSHAgent(client, privateKeys, promptForPassphrase)
}

func addPrivateKeysToAgent(client agent.Agent, privateKeys []string, promptForPassphrase func(file string) ([]byte, error)) error {
	for _, pk := range privateKeys {
		key, err := readPrivateKeyFromFile(pk, promptForPassphrase)
		if err != nil {
			return err
		}

		if err := client.Add(agent.AddedKey{
			PrivateKey: key,
		}); err != nil {
			return err
		}
	}

	return nil
}

func signerFromFile(file string, promptForPassphrase func(file string) ([]byte, error)) (ssh.Signer, error) {
	key, err := readPrivateKeyFromFile(file, promptForPassphrase)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(key)
}

func readPrivateKeyFromFile(file string, promptForPassphrase func(file string) ([]byte, error)) (interface{}, error) {
	pb, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParseRawPrivateKey(pb)
	if err == nil {
		return key, err
	}

	var e *ssh.PassphraseMissingError
	if !errors.As(err, &e) && !strings.Contains(err.Error(), errCannotDecodeEncryptedPrivateKeys) {
		return nil, err
	}

	// simulate ssh client to retry 3 times
	for i := 0; i < 3; i++ {
		pass, err := promptForPassphrase(file)
		if err != nil {
			return nil, err
		}

		key, err := ssh.ParseRawPrivateKeyWithPassphrase(pb, bytes.TrimSpace(pass))
		if err == nil {
			return key, nil
		}

		if !errors.Is(err, x509.IncorrectPasswordError) {
			return nil, err
		}
	}

	return nil, &errDescryptingPrivateKey{file}
}

func readPublicKeysBestEfforts(privateKeys []string) []ssh.PublicKey {
	var pks []ssh.PublicKey
	for _, file := range privateKeys {
		pb, err := ioutil.ReadFile(file + ".pub")
		if err != nil {
			continue
		}

		pk, _, _, _, err := ssh.ParseAuthorizedKey(pb)
		if err != nil {
			continue
		}

		pks = append(pks, pk)
	}

	return pks
}

func promptForPassphrase(file string) ([]byte, error) {
	defer fmt.Println("") // clear return

	fmt.Printf("Enter passphrase for key '%s': ", file)

	return terminal.ReadPassword(int(syscall.Stdin))
}
