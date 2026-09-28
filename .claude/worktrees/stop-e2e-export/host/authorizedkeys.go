package host

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

type AuthorizedKey struct {
	PublicKeys []ssh.PublicKey
	Comment    string
}

func AuthorizedKeysFromFile(file string) (*AuthorizedKey, error) {
	authorizedKeysBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("error reading authorized keys file %s: %w", file, err)
	}

	return parseAuthorizedKeys(authorizedKeysBytes, file)
}

func parseAuthorizedKeys(keysBytes []byte, comment string) (*AuthorizedKey, error) {
	var authorizedKeys []ssh.PublicKey
	for len(keysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(keysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeys = append(authorizedKeys, pubKey)
		keysBytes = rest
	}

	// An empty body parses "successfully" into zero keys, and an empty
	// authorized-key set means "allow anyone" downstream
	// (host/internal/server.go). Refuse it here so neither an empty file nor a
	// zero-length HTTP response can silently open a session.
	if len(authorizedKeys) == 0 {
		return nil, fmt.Errorf("no public keys found in %s", comment)
	}

	return &AuthorizedKey{
		PublicKeys: authorizedKeys,
		Comment:    comment,
	}, nil
}
