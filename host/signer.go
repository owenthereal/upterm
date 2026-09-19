package host

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
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

// SignerOptions configures SignersWith.
type SignerOptions struct {
	PrivateKeys []string
	// Passphrase is asked for an encrypted key's passphrase. Nil prompts on
	// this process's terminal, which a daemon does not have.
	Passphrase func(file string) ([]byte, error)
	// OnSkip is told about a key file that was skipped and why. Nil is
	// silent, as SignersFromFiles always was.
	OnSkip func(file string, err error)
}

// Signers returns signers from the agent, then the files, then a key made
// on the spot, prompting for passphrases on this process's terminal.
func Signers(privateKeys []string) ([]ssh.Signer, func(), error) {
	return SignersWith(SignerOptions{PrivateKeys: privateKeys})
}

// SignersWith is Signers with the passphrase prompt and the skip report
// injected.
func SignersWith(opts SignerOptions) ([]ssh.Signer, func(), error) {
	signers, cleanup, err := signersFromSSHAgent(os.Getenv("SSH_AUTH_SOCK"))
	if len(signers) == 0 || err != nil {
		signers, err = SignersFromFilesWith(opts.PrivateKeys, opts.Passphrase, opts.OnSkip)
	}
	if len(signers) == 0 || err != nil {
		signers, err = utils.CreateSigners(nil)
	}
	return signers, cleanup, err
}

func SignersFromFiles(privateKeys []string) ([]ssh.Signer, error) {
	return SignersFromFilesWith(privateKeys, nil, nil)
}

// SignersFromFilesWith reads every key it can and skips the rest. A key that
// cannot be read never fails the set: the default key list is every file in
// ~/.ssh that exists, and one unreadable file must not stop a session.
func SignersFromFilesWith(privateKeys []string, passphrase func(string) ([]byte, error), onSkip func(string, error)) ([]ssh.Signer, error) {
	if passphrase == nil {
		passphrase = promptForPassphrase
	}
	var signers []ssh.Signer
	for _, file := range privateKeys {
		s, err := signerFromFile(file, passphrase)
		if err != nil {
			if onSkip != nil {
				onSkip(file, err)
			}
			continue
		}
		signers = append(signers, s)
	}
	return signers, nil
}

func signersFromSSHAgent(socket string) ([]ssh.Signer, func(), error) {
	cleanup := func() {}
	if socket == "" {
		return nil, cleanup, fmt.Errorf("SSH Agent is not running")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { _ = conn.Close() }

	client := agent.NewClient(conn)
	signers, err := client.Signers()

	return signers, cleanup, err
}

func signerFromFile(file string, promptForPassphrase func(file string) ([]byte, error)) (ssh.Signer, error) {
	key, err := readPrivateKeyFromFile(file, promptForPassphrase)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(key)
}

func readPrivateKeyFromFile(file string, promptForPassphrase func(file string) ([]byte, error)) (interface{}, error) {
	pb, err := os.ReadFile(file)
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

func promptForPassphrase(file string) ([]byte, error) {
	defer fmt.Println("") // clear return

	fmt.Printf("Enter passphrase for key '%s': ", file)

	return term.ReadPassword(int(syscall.Stdin))
}
