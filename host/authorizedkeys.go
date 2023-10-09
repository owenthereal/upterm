package host

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
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

	return parseAuthorizedKeys(authorizedKeysBytes)
}

func GitHubUserAuthorizedKeys(usernames []string) ([]ssh.PublicKey, error) {
	var (
		authorizedKeys []ssh.PublicKey
		seen           = make(map[string]bool)
	)
	for _, username := range usernames {
		if _, found := seen[username]; !found {
			seen[username] = true

			pks, err := githubUserPublicKeys(username)
			if err != nil {
				return nil, err
			}

			aks, err := parseAuthorizedKeys(pks)
			if err != nil {
				return nil, err
			}

			authorizedKeys = append(authorizedKeys, aks...)
		}
	}

	return authorizedKeys, nil
}

func GitLabUserAuthorizedKeys(usernames []string) ([]ssh.PublicKey, error) {
	return usersPublicKeys(gitLabKeysUrlFmt, usernames)
}

func SourceHutUserAuthorizedKeys(usernames []string) ([]ssh.PublicKey, error) {
	return usersPublicKeys(sourceHutKeysUrlFmt, usernames)
}

func parseAuthorizedKeys(keysBytes []byte) ([]ssh.PublicKey, error) {
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

func githubUserPublicKeys(username string) ([]byte, error) {
	client, err := api.DefaultRESTClient()
	if err != nil {
		if strings.Contains(err.Error(), "authentication token not found for host") {
			// fallback to use the public GH API
			return userPublicKeys(gitHubKeysUrlFmt, username)
		}

		return nil, err
	}

	keys := []struct {
		Key string `json:"key"`
	}{}
	if err := client.Get(fmt.Sprintf("users/%s/keys", url.PathEscape(username)), &keys); err != nil {
		return nil, err
	}

	var authorizedKeys []string
	for _, key := range keys {
		authorizedKeys = append(authorizedKeys, key.Key)
	}

	return []byte(strings.Join(authorizedKeys, "\n")), nil
}

func usersPublicKeys(urlFmt string, usernames []string) ([]ssh.PublicKey, error) {
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
			userKeys, err := parseAuthorizedKeys(keyBytes)
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
