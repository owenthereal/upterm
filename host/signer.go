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

	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
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

// Signers return signers based on the folllowing conditions:
// If private key is not supplied, it returns signers from SSH agent; If SSH agent returns no signer, it generates a private key and returns the corresponding signer.
// If private key is supplied, it returns signers from SSH agent with matching private keys and adds priavte keys to SSH agent where possible; If there is an error, it falls back to return signers from files
func Signers(privateKeys []string) ([]ssh.Signer, func(), error) {
	var (
		socket  = os.Getenv("SSH_AUTH_SOCK")
		signers []ssh.Signer
		cleanup func()
		err     error
	)

	if len(privateKeys) == 0 {
		signers, cleanup, err = SignersFromSSHAgent(socket)
		if err != nil {
			signers, err = utils.CreateSigners(nil)
		}

		return signers, cleanup, err
	}

	signers, cleanup, err = SignersFromSSHAgentForKeys(socket, privateKeys)
	if err != nil {
		signers, err = SignersFromFiles(privateKeys)
	}

	return signers, cleanup, err
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

// SignersFromSSHAgent returns all signers from SSH agent
func SignersFromSSHAgent(socket string) ([]ssh.Signer, func(), error) {
	return SignersFromSSHAgentForKeys(socket, nil)
}

// SignersFromSSHAgentForKeys retruns signers from SSH agent for matching private keys.
// It also adds private key to SSH agent where possbile which simulates the behavior of ssh
func SignersFromSSHAgentForKeys(socket string, privateKeys []string) ([]ssh.Signer, func(), error) {
	cleanup := func() {}
	if socket == "" {
		return nil, cleanup, fmt.Errorf("SSH Agent is not running")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, cleanup, err
	}

	cleanup = func() { conn.Close() }
	signers, err := signersFromSSHAgentForKeys(agent.NewClient(conn), privateKeys, promptForPassphrase)

	return signers, cleanup, err
}

func signersFromSSHAgentForKeys(client agent.Agent, privateKeys []string, promptForPassphrase func(file string) ([]byte, error)) ([]ssh.Signer, error) {
	// Return all signers from SSH agent if no private key is specified
	if len(privateKeys) == 0 {
		signers, err := client.Signers()
		if err != nil {
			return nil, err
		}

		if len(signers) == 0 {
			return nil, fmt.Errorf("SSH Agent does not contain any identities")
		}

		return signers, nil
	}

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

	return signersFromSSHAgentForKeys(client, privateKeys, promptForPassphrase)
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

	return term.ReadPassword(int(syscall.Stdin))
}
