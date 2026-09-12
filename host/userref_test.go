package host

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ParseUserRef(t *testing.T) {
	pinGitHubHost(t, "github.com")

	cases := []struct {
		name        string
		in          string
		wantKeysURL string
		wantDisplay string
		wantMode    CredentialMode
	}{
		{
			name:        "github shorthand",
			in:          "github:alice",
			wantKeysURL: "https://github.com/alice.keys",
			wantDisplay: "github:alice@github.com",
			wantMode:    CredentialDefault,
		},
		{
			name:        "github enterprise",
			in:          "github:bob@ghe.corp.com",
			wantKeysURL: "https://ghe.corp.com/bob.keys",
			wantDisplay: "github:bob@ghe.corp.com",
			wantMode:    CredentialHostScoped,
		},
		{
			name:        "gitea requires and accepts a host",
			in:          "gitea:carol@git.corp.com",
			wantKeysURL: "https://git.corp.com/carol.keys",
			wantDisplay: "gitea:carol@git.corp.com",
			wantMode:    CredentialNone,
		},
		{
			name:        "non-default port",
			in:          "gitea:carol@git.corp.com:3000",
			wantKeysURL: "https://git.corp.com:3000/carol.keys",
			wantDisplay: "gitea:carol@git.corp.com:3000",
			wantMode:    CredentialNone,
		},
		{
			name:        "sourcehut adds the tilde",
			in:          "srht:dave",
			wantKeysURL: "https://meta.sr.ht/~dave.keys",
			wantDisplay: "srht:dave@meta.sr.ht",
			wantMode:    CredentialNone,
		},
		{
			name:        "sourcehut accepts an explicit tilde",
			in:          "srht:~dave",
			wantKeysURL: "https://meta.sr.ht/~dave.keys",
			wantDisplay: "srht:dave@meta.sr.ht",
			wantMode:    CredentialNone,
		},
		{
			name:        "gitlab shorthand",
			in:          "gitlab:erin",
			wantKeysURL: "https://gitlab.com/erin.keys",
			wantDisplay: "gitlab:erin@gitlab.com",
			wantMode:    CredentialNone,
		},
		{
			name:        "codeberg shorthand",
			in:          "codeberg:frank",
			wantKeysURL: "https://codeberg.org/frank.keys",
			wantDisplay: "codeberg:frank@codeberg.org",
			wantMode:    CredentialNone,
		},
		{
			name:        "raw url gets .keys appended",
			in:          "https://git.corp.com/bob",
			wantKeysURL: "https://git.corp.com/bob.keys",
			wantDisplay: "https://git.corp.com/bob.keys",
			wantMode:    CredentialNone,
		},
		{
			name:        "raw url already ending in .keys is not doubled",
			in:          "https://git.corp.com/bob.keys",
			wantKeysURL: "https://git.corp.com/bob.keys",
			wantDisplay: "https://git.corp.com/bob.keys",
			wantMode:    CredentialNone,
		},
		{
			name:        "raw url trailing slash is stripped",
			in:          "https://git.corp.com/team-a/bob/",
			wantKeysURL: "https://git.corp.com/team-a/bob.keys",
			wantDisplay: "https://git.corp.com/team-a/bob.keys",
			wantMode:    CredentialNone,
		},
		{
			// Mutating u.Path without RawPath re-encodes the decoded path and
			// turns %2F into a real separator, pointing at a different endpoint.
			name:        "raw url keeps an escaped separator escaped",
			in:          "https://git.corp.com/team%2Falice",
			wantKeysURL: "https://git.corp.com/team%2Falice.keys",
			wantDisplay: "https://git.corp.com/team%2Falice.keys",
			wantMode:    CredentialNone,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, err := ParseUserRef(c.in)
			require.NoError(t, err)
			assert.Equal(t, c.wantKeysURL, ref.KeysURL())
			assert.Equal(t, c.wantDisplay, ref.Display())
			assert.Equal(t, c.wantMode, ref.Mode)
			assert.Equal(t, c.in, ref.Raw)
		})
	}
}

func Test_ParseUserRef_errors(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		wantErrSubstr string
	}{
		{name: "empty", in: "", wantErrSubstr: "empty user reference"},
		{name: "no provider", in: "alice", wantErrSubstr: "missing provider"},
		{name: "unknown provider", in: "bitbucket:alice", wantErrSubstr: "unknown provider"},
		{name: "gitea without a host", in: "gitea:alice", wantErrSubstr: "requires a host"},
		{name: "forgejo without a host", in: "forgejo:alice", wantErrSubstr: "requires a host"},
		{name: "missing username", in: "github:", wantErrSubstr: "missing username"},
		{name: "missing username with host", in: "github:@ghe.corp.com", wantErrSubstr: "missing username"},
		{name: "plaintext url", in: "http://git.corp.com/bob", wantErrSubstr: "refusing to fetch keys over http://"},
		{name: "url with credentials", in: "https://u:p@git.corp.com/bob", wantErrSubstr: "must not contain credentials"},
		{name: "url with query", in: "https://git.corp.com/bob?x=1", wantErrSubstr: "must not contain a query or fragment"},
		{name: "url with fragment", in: "https://git.corp.com/bob#f", wantErrSubstr: "must not contain a query or fragment"},
		{name: "url without a path", in: "https://git.corp.com", wantErrSubstr: "must include a user path"},
		{name: "port on github.com", in: "github:alice@github.com:8443", wantErrSubstr: "does not accept a port"},
		{name: "port on a tenancy host", in: "github:alice@acme.ghe.com:8443", wantErrSubstr: "does not accept a port"},
		{name: "trailing @ with no host", in: "github:alice@", wantErrSubstr: "missing host after '@'"},
		{name: "host with a path", in: "gitea:alice@git.corp.com/sub", wantErrSubstr: "expected host or host:port"},
		{name: "host with a query", in: "gitea:alice@git.corp.com?x=1", wantErrSubstr: "expected host or host:port"},
		{name: "host with a fragment", in: "gitea:alice@git.corp.com#f", wantErrSubstr: "expected host or host:port"},
		{name: "non-numeric port", in: "gitea:alice@git.corp.com:http", wantErrSubstr: "invalid port"},
		{name: "url without a host", in: "https:///alice", wantErrSubstr: "URL must include a host"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseUserRef(c.in)
			assert.ErrorContains(t, err, c.wantErrSubstr)
		})
	}
}

// pinGitHubHost fixes go-gh's default host. Clearing GH_HOST is not enough:
// go-gh also reads the developer's ~/.config/gh/hosts.yml, so an unpinned test
// can pick up a different default on someone else's machine.
func pinGitHubHost(t *testing.T, host string) {
	t.Helper()
	restore := defaultGitHubHost
	defaultGitHubHost = func() string { return host }
	t.Cleanup(func() { defaultGitHubHost = restore })
}

func Test_ParseUserRef_honorsGHHost(t *testing.T) {
	pinGitHubHost(t, "ghe.corp.com")

	ref, err := ParseUserRef("github:alice")
	require.NoError(t, err)

	// A reference with no explicit @host defers to go-gh's own host and token resolution,
	// preserving the previously undocumented GH_HOST behavior.
	assert.Equal(t, "ghe.corp.com", ref.ResolveHost())
	assert.Equal(t, "github:alice@ghe.corp.com", ref.Display())
	assert.Equal(t, CredentialDefault, ref.Mode)
}

func Test_githubAPIPrefix(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		{name: "github.com", host: "github.com", want: "https://api.github.com/"},
		{name: "github.com subdomain normalizes", host: "foo.github.com", want: "https://api.github.com/"},
		{name: "tenancy host has no api/v3", host: "acme.ghe.com", want: "https://api.acme.ghe.com/"},
		{name: "tenancy subdomain normalizes", host: "sub.acme.ghe.com", want: "https://api.acme.ghe.com/"},
		{name: "enterprise server", host: "ghe.corp.com", want: "https://ghe.corp.com/api/v3/"},
		{name: "enterprise server with a port", host: "ghe.corp.com:8443", want: "https://ghe.corp.com:8443/api/v3/"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, githubAPIPrefix(c.host))
		})
	}
}

func Test_githubClientConfig(t *testing.T) {
	cases := []struct {
		name           string
		ref            string
		wantAPIURL     string
		wantClientHost string
		wantOrigin     string
	}{
		{
			name:           "github.com uses the api subdomain",
			ref:            "github:alice@github.com",
			wantAPIURL:     "https://api.github.com/users/alice/keys",
			wantClientHost: "github.com",
			wantOrigin:     "api.github.com",
		},
		{
			// The alias normalizes to github.com, so the request goes to
			// api.github.com. Passing the unnormalized alias as the client
			// host makes go-gh's isSameDomain fail and drops the token.
			name:           "github.com alias normalizes for credential matching",
			ref:            "github:alice@foo.github.com",
			wantAPIURL:     "https://api.github.com/users/alice/keys",
			wantClientHost: "github.com",
			wantOrigin:     "api.github.com",
		},
		{
			name:           "tenancy host has no api/v3",
			ref:            "github:alice@acme.ghe.com",
			wantAPIURL:     "https://api.acme.ghe.com/users/alice/keys",
			wantClientHost: "acme.ghe.com",
			wantOrigin:     "api.acme.ghe.com",
		},
		{
			name:           "tenancy alias normalizes",
			ref:            "github:alice@sub.acme.ghe.com",
			wantAPIURL:     "https://api.acme.ghe.com/users/alice/keys",
			wantClientHost: "acme.ghe.com",
			wantOrigin:     "api.acme.ghe.com",
		},
		{
			name:           "enterprise server",
			ref:            "github:alice@ghe.corp.com",
			wantAPIURL:     "https://ghe.corp.com/api/v3/users/alice/keys",
			wantClientHost: "ghe.corp.com",
			wantOrigin:     "ghe.corp.com",
		},
		{
			name:           "enterprise server on a non-default port",
			ref:            "github:alice@ghe.corp.com:8443",
			wantAPIURL:     "https://ghe.corp.com:8443/api/v3/users/alice/keys",
			wantClientHost: "ghe.corp.com",
			wantOrigin:     "ghe.corp.com:8443",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref, err := ParseUserRef(c.ref)
			require.NoError(t, err)

			apiURL, clientHost, origin, err := githubClientConfig(ref)
			require.NoError(t, err)

			assert.Equal(t, c.wantAPIURL, apiURL)
			assert.Equal(t, c.wantClientHost, clientHost)
			assert.Equal(t, c.wantOrigin, origin)
		})
	}
}
