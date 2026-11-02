package host

import (
	"fmt"
	"os"

	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

type AuthorizedKey struct {
	PublicKeys []ssh.PublicKey
	Comment    string

	// guest is who the keys belong to, as the approval review names a guest
	// with one: an --authorized-user's user and reference (UserRef.guest).
	// Empty for keys from a file or a raw URL, which name no one.
	guest string
}

// guestLabels names, by fingerprint, the guest each key in aks belongs to,
// for the approval review to say who is asking: the user an --authorized-user
// named, "alice (github:alice)", or else, for an entry that names no one,
// such as an authorized_keys file, which can hold several guests' keys, the
// key and where it came from, "a guest with key SHA256:… from
// /home/alice/.ssh/authorized_keys". A key on more than one entry is named by
// the first that names someone.
func guestLabels(aks []*AuthorizedKey) map[string]string {
	labels := make(map[string]string)
	for _, named := range []bool{true, false} {
		for _, ak := range aks {
			if (ak.guest != "") != named {
				continue
			}
			for _, key := range ak.PublicKeys {
				fingerprint := utils.FingerprintSHA256(key)
				if labels[fingerprint] != "" {
					continue
				}
				label := ak.guest
				if label == "" {
					label = "a guest with key " + fingerprint
					if ak.Comment != "" {
						label += " from " + ak.Comment
					}
				}
				labels[fingerprint] = label
			}
		}
	}
	return labels
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
