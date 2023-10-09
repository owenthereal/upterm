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
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	gitHubKeysUrlFmt    = "https://github.com/%s"
	gitLabKeysUrlFmt    = "https://gitlab.com/%s"
	sourceHutKeysUrlFmt = "https://meta.sr.ht/~%s"
)

type AuthorizedKey struct {
	PublicKeys []ssh.PublicKey
	Comment    string
}

func AuthorizedKeysFromFile(file string) (*AuthorizedKey, error) {
	authorizedKeysBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, nil
	}

	return parseAuthorizedKeys(authorizedKeysBytes, file)
}

func GitHubUserAuthorizedKeys(usernames []string, logger *logrus.Logger) ([]*AuthorizedKey, error) {
	var (
		authorizedKeys []*AuthorizedKey
		seen           = make(map[string]bool)
	)
	for _, username := range usernames {
		if _, found := seen[username]; !found {
			seen[username] = true

			pks, err := githubUserPublicKeys(username, logger)
			if err != nil {
				return nil, err
			}

			aks, err := parseAuthorizedKeys(pks, username)
			if err != nil {
				return nil, err
			}

			authorizedKeys = append(authorizedKeys, aks)
		}
	}

	return authorizedKeys, nil
}

func GitLabUserAuthorizedKeys(usernames []string) ([]*AuthorizedKey, error) {
	return usersPublicKeys(gitLabKeysUrlFmt, usernames)
}

func SourceHutUserAuthorizedKeys(usernames []string) ([]*AuthorizedKey, error) {
	return usersPublicKeys(sourceHutKeysUrlFmt, usernames)
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

	return &AuthorizedKey{
		PublicKeys: authorizedKeys,
		Comment:    comment,
	}, nil
}

func githubUserPublicKeys(username string, logger *logrus.Logger) ([]byte, error) {
	client, err := api.DefaultRESTClient()
	if err != nil {
		if strings.Contains(err.Error(), "authentication token not found for host") {
			// fallback to use the public GH API
			logger.WithError(err).Warn("no GitHub token found, falling back to public API")
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

func usersPublicKeys(urlFmt string, usernames []string) ([]*AuthorizedKey, error) {
	var (
		authorizedKeys []*AuthorizedKey
		seen           = make(map[string]bool)
	)
	for _, username := range usernames {
		if _, found := seen[username]; !found {
			seen[username] = true

			keyBytes, err := userPublicKeys(urlFmt, username)
			if err != nil {
				return nil, fmt.Errorf("[%s]: %s", username, err)
			}
			userKeys, err := parseAuthorizedKeys(keyBytes, username)
			if err != nil {
				return nil, fmt.Errorf("[%s]: %s", username, err)
			}

			authorizedKeys = append(authorizedKeys, userKeys)
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
