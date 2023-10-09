package host

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	gitHubKeysUrlFmt    = "https://github.com/%s"
	gitLabKeysUrlFmt    = "https://gitlab.com/%s"
	sourceHutKeysUrlFmt = "https://meta.sr.ht/~%s"
)

func AuthorizedKeysFromFile(file string) ([]ssh.PublicKey, error) {
	authorizedKeysBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, nil
	}

	return parseKeys(authorizedKeysBytes)
}

func GitHubUserAuthorizedKeys(usernames []string) ([]ssh.PublicKey, error) {
	return publicKeys(gitHubKeysUrlFmt, usernames)
}

func GitLabUserAuthorizedKeys(usernames []string) ([]ssh.PublicKey, error) {
	return publicKeys(gitLabKeysUrlFmt, usernames)
}

func SourceHutUserAuthorizedKeys(usernames []string) ([]ssh.PublicKey, error) {
	return publicKeys(sourceHutKeysUrlFmt, usernames)
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

func publicKeys(urlFmt string, usernames []string) ([]ssh.PublicKey, error) {
	var (
		authorizedKeys []ssh.PublicKey
		seen           = make(map[string]bool)
	)
	for _, username := range usernames {
		if _, found := seen[username]; !found {
			seen[username] = true

			keyBytes, err := userPublicKeys(urlFmt, username)
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

func userPublicKeys(urlFmt string, username string) ([]byte, error) {
	path := url.PathEscape(fmt.Sprintf("%s.keys", username))

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(fmt.Sprintf(urlFmt, path))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}
