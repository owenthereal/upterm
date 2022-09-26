package host

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	gitHubKeysUrlFmt                    = "https://github.com/%s"
	gitLabKeysUrlFmt                    = "https://gitlab.com/%s"
)

type errDescryptingPrivateKey struct {
	file string
}

func (e *errDescryptingPrivateKey) Error() string {
	return fmt.Sprintf("error decrypting private key %s", e.file)
}

func parseKeys(keysBytes []byte) ([]ssh.PublicKey, error) {
	var authorizedKeys []ssh.PublicKey
	for len(keysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(keysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeys = append(authorizedKeys, pubKey)
		keysBytes = rest
	}

	return authorizedKeys, nil
}

func AuthorizedKeys(file string) ([]ssh.PublicKey, error) {
	authorizedKeysBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, nil
	}

	return parseKeys(authorizedKeysBytes)
}

func getUserPublicKeys(urlFmt string, username string) ([]byte, error) {
	path := url.PathEscape(fmt.Sprintf("%s.keys", username))
	resp, err := http.Get(fmt.Sprintf(urlFmt, path))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func getPublicKeys(urlFmt string, usernames []string) ([]ssh.PublicKey, error) {
	var authorizedKeys []ssh.PublicKey
	seen := make(map[string]bool)
	for _, username := range usernames {
		if _, found := seen[username]; !found {
			seen[username] = true
			keyBytes, err := getUserPublicKeys(urlFmt, username)
			if err != nil {
				return nil, fmt.Errorf("[%s]: %s", username, err)
			}
			userKeys, err := parseKeys(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("[%s]: %s", username, err)
			}
			authorizedKeys = append(authorizedKeys, userKeys...)
		}
	}
	return authorizedKeys, nil
}

func GitHubUserKeys(usernames []string) ([]ssh.PublicKey, error) {
	return getPublicKeys(gitHubKeysUrlFmt, usernames)
}

func GitLabUserKeys(usernames []string) ([]ssh.PublicKey, error) {
	return getPublicKeys(gitLabKeysUrlFmt, usernames)
}

// Signers return signers based on the folllowing conditions:
// If SSH agent is running and has keys, it returns signers from SSH agent, otherwise return signers from private keys;
// If neither works, it generates a signer on the fly.
func Signers(privateKeys []string) ([]ssh.Signer, func(), error) {
	var (
		signers []ssh.Signer
		cleanup func()
		err     error
	)

	signers, cleanup, err = signersFromSSHAgent(os.Getenv("SSH_AUTH_SOCK"))
	if len(signers) == 0 || err != nil {
		signers, err = SignersFromFiles(privateKeys)
	}

	if len(signers) == 0 || err != nil {
		signers, err = utils.CreateSigners(nil)
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

func signersFromSSHAgent(socket string) ([]ssh.Signer, func(), error) {
	cleanup := func() {}
	if socket == "" {
		return nil, cleanup, fmt.Errorf("SSH Agent is not running")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { conn.Close() }

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
