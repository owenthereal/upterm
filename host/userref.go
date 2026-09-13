package host

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cli/go-gh/v2/pkg/auth"
)

// CredentialMode describes how a reference selects an authentication token.
type CredentialMode int

const (
	// CredentialNone never sends a credential. Every provider but GitHub.
	CredentialNone CredentialMode = iota
	// CredentialDefault defers to go-gh's own host and token resolution,
	// preserving GH_HOST and the enterprise environment variables. Used when a
	// GitHub reference names no explicit host.
	CredentialDefault
	// CredentialHostScoped uses only credentials stored for the named host.
	// GH_ENTERPRISE_TOKEN and GITHUB_ENTERPRISE_TOKEN are not host-scoped, so
	// honoring them here would send one instance's token to another.
	CredentialHostScoped
)

// UserRef is one parsed --authorized-user value.
type UserRef struct {
	Provider string // "" for the raw-URL form
	User     string
	Host     string // host[:port] as written; "" means "provider default"
	URL      string // raw-URL form only: the complete .keys URL
	Raw      string // the original string, for error messages
	Mode     CredentialMode
}

type providerInfo struct {
	defaultHost string // "" means a host is required
	userPrefix  string // "~" for SourceHut
}

var providers = map[string]providerInfo{
	"github":   {defaultHost: "github.com"},
	"gitlab":   {defaultHost: "gitlab.com"},
	"codeberg": {defaultHost: "codeberg.org"},
	"gitea":    {},
	"forgejo":  {},
	"srht":     {defaultHost: "meta.sr.ht", userPrefix: "~"},
}

const providerList = "github, gitlab, gitea, forgejo, codeberg, srht"

// defaultGitHubHost is a variable so tests can pin it. It returns whatever
// go-gh considers the default host, which honors GH_HOST.
var defaultGitHubHost = func() string {
	host, _ := auth.DefaultHost()
	return host
}

// ParseUserRef parses a reference of the form provider:user,
// provider:user@host, or an https:// URL. It performs no I/O.
func ParseUserRef(s string) (UserRef, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return UserRef{}, fmt.Errorf("empty user reference")
	}

	if strings.HasPrefix(strings.ToLower(s), "http://") {
		return UserRef{}, fmt.Errorf("%s: refusing to fetch keys over http://; keys fetched over plaintext can be forged by anyone on the network path. Use https, or save the keys to a file and pass --authorized-keys", s)
	}
	if strings.HasPrefix(strings.ToLower(s), "https://") {
		return parseRawURLRef(s)
	}

	provider, rest, found := strings.Cut(s, ":")
	if !found {
		return UserRef{}, fmt.Errorf("%s: missing provider; use one of %s, or an https:// URL", s, providerList)
	}

	info, ok := providers[provider]
	if !ok {
		return UserRef{}, fmt.Errorf("%s: unknown provider %q; use one of %s", s, provider, providerList)
	}

	user, host := rest, ""
	explicitHost := false
	// Split on the last @: no supported forge allows @ in a username, but the
	// last separator is the unambiguous one regardless.
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		user, host = rest[:i], rest[i+1:]
		explicitHost = true
	}

	// Only SourceHut writes the ~ as part of the name, and KeysURL() re-adds it
	// from providerInfo.userPrefix. Stripping unconditionally turned
	// github:~alice into github:alice silently.
	if info.userPrefix == "~" {
		user = strings.TrimPrefix(user, "~")
	}
	if user == "" {
		return UserRef{}, fmt.Errorf("%s: missing username", s)
	}
	// A ~ still leading here is either a provider that has no tilde form or a
	// doubled ~~, which would request https://meta.sr.ht/~~alice.keys.
	if strings.HasPrefix(user, "~") {
		return UserRef{}, fmt.Errorf("%s: invalid username %q: unexpected '~' prefix", s, user)
	}
	if strings.ContainsAny(user, "/?#") {
		return UserRef{}, fmt.Errorf("%s: invalid username %q", s, user)
	}

	if explicitHost {
		// Validated rather than merely non-empty: "github:alice@" would
		// otherwise fall through to the provider default and silently
		// re-enable ambient credential resolution, which is exactly what an
		// explicit host is supposed to turn off.
		if err := validateHost(host); err != nil {
			return UserRef{}, fmt.Errorf("%s: %w", s, err)
		}
	} else if info.defaultHost == "" {
		return UserRef{}, fmt.Errorf("%s: %s requires a host, e.g. %s:%s@git.example.com", s, provider, provider, user)
	}

	mode := CredentialNone
	if provider == "github" {
		if explicitHost {
			mode = CredentialHostScoped
		} else {
			mode = CredentialDefault
		}

		if hostname, port := splitHostPort(host); port != "" {
			// github.com and *.ghe.com are SaaS origins; a port there is
			// always a mistake, and go-gh would silently drop the token
			// because it compares a port-less hostname against ClientOptions.Host.
			if !auth.IsEnterprise(auth.NormalizeHostname(hostname)) {
				return UserRef{}, fmt.Errorf("%s: %s does not accept a port", s, hostname)
			}
		}
	}

	return UserRef{
		Provider: provider,
		User:     user,
		Host:     host,
		Raw:      s,
		Mode:     mode,
	}, nil
}

// validateHost checks an explicit host[:port] authority.
func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("missing host after '@'")
	}
	if strings.ContainsAny(host, "/?#@") {
		return fmt.Errorf("invalid host %q: expected host or host:port", host)
	}

	hostname, port := splitHostPort(host)
	if hostname == "" {
		return fmt.Errorf("invalid host %q: expected host or host:port", host)
	}

	// Whether a port section exists cannot be read off port alone:
	// net.SplitHostPort reports an empty port for "host:" without error, and
	// reports no port at all for "host:1:2". Both used to pass. An empty port
	// is not harmless — KeysURL() then emits https://host:/alice.keys, which
	// works and whose dedup key differs from the same host without the colon.
	if strings.LastIndex(host, ":") > strings.LastIndex(host, "]") {
		if _, _, err := net.SplitHostPort(host); err != nil {
			return fmt.Errorf("invalid host %q: expected host or host:port", host)
		}
		// Itoa round trip as well as the range check: it rejects "007" and
		// "+7", which Atoi accepts and which then name a different authority
		// than the port they denote.
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return fmt.Errorf("invalid port %q in host %q", port, host)
		}
	}
	if _, err := url.Parse("https://" + host); err != nil {
		return fmt.Errorf("invalid host %q: %w", host, err)
	}
	return nil
}

func parseRawURLRef(s string) (UserRef, error) {
	u, err := url.Parse(s)
	if err != nil {
		return UserRef{}, fmt.Errorf("%s: %w", s, err)
	}
	if u.User != nil {
		return UserRef{}, fmt.Errorf("%s: URL must not contain credentials", s)
	}
	// ForceQuery as well as RawQuery: "https://git.corp.com/alice?" has an empty
	// RawQuery yet still renders the "?" back out of url.String(), so the
	// request would carry a query the spec forbids.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return UserRef{}, fmt.Errorf("%s: URL must not contain a query or fragment", s)
	}
	if u.Hostname() == "" {
		return UserRef{}, fmt.Errorf("%s: URL must include a host", s)
	}

	escaped := strings.TrimSuffix(u.EscapedPath(), "/")
	if escaped == "" {
		return UserRef{}, fmt.Errorf("%s: URL must include a user path, e.g. https://git.example.com/alice", s)
	}
	if !strings.HasSuffix(escaped, ".keys") {
		escaped += ".keys"
	}

	// Set RawPath alongside Path. Mutating Path alone leaves RawPath stale, so
	// url.String() re-encodes from the decoded path and turns an escaped
	// separator into a real one: /team%2Falice would become /team/alice.keys,
	// silently pointing at a different endpoint.
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return UserRef{}, fmt.Errorf("%s: %w", s, err)
	}
	u.Path = decoded
	u.RawPath = escaped

	return UserRef{
		URL:  u.String(),
		Raw:  s,
		Mode: CredentialNone,
	}, nil
}

// githubClientConfig derives the three hosts a GitHub fetch needs. They are not
// interchangeable:
//
//   - apiURL is where the request goes.
//   - clientHost is what go-gh matches against when attaching credentials. It
//     must be the *normalized* hostname: go-gh's isSameDomain compares the
//     request's hostname against this value, and for an alias such as
//     foo.github.com the request targets api.github.com, which does not match
//     the unnormalized alias — the token would be silently dropped.
//   - origin is the exact host:port allowed to receive the credential. That is
//     the API origin (api.github.com), not the website host (github.com);
//     scoping to the website host would strip the token from every legitimate
//     request.
func githubClientConfig(ref UserRef) (apiURL, clientHost, origin string, err error) {
	host := ref.ResolveHost()
	hostname, _ := splitHostPort(host)

	// per_page=100 is the API maximum; githubUserKeys then follows
	// Link: rel="next" for whatever does not fit. Both halves matter: the
	// endpoint defaults to 30 per page, and a user with more keys than one
	// page holds would otherwise silently lose the rest on the authenticated
	// path while the anonymous .keys fallback returns all of them.
	apiURL = githubAPIPrefix(host) + "users/" + url.PathEscape(ref.User) + "/keys?per_page=100"
	parsed, err := url.Parse(apiURL)
	if err != nil {
		return "", "", "", err
	}

	return apiURL, auth.NormalizeHostname(hostname), parsed.Host, nil
}

// ResolveHost returns the host[:port] this reference targets.
func (r UserRef) ResolveHost() string {
	if r.URL != "" {
		if u, err := url.Parse(r.URL); err == nil {
			return u.Host
		}
		return ""
	}
	if r.Host != "" {
		return r.Host
	}
	if r.Provider == "github" {
		return defaultGitHubHost()
	}
	return providers[r.Provider].defaultHost
}

// KeysURL returns the endpoint serving this user's authorized_keys body.
func (r UserRef) KeysURL() string {
	if r.URL != "" {
		return r.URL
	}
	return "https://" + r.ResolveHost() + "/" +
		providers[r.Provider].userPrefix + url.PathEscape(r.User) + ".keys"
}

// Display is the resolved identity used as AuthorizedKey.Comment. It names the
// host actually contacted, which the verbatim input does not when GH_HOST is
// in play.
func (r UserRef) Display() string {
	if r.URL != "" {
		return r.URL
	}
	return r.Provider + ":" + r.User + "@" + r.ResolveHost()
}

// githubAPIPrefix mirrors go-gh's unexported restPrefix, which is not simply
// "github.com or /api/v3": GitHub Enterprise Cloud at *.ghe.com is not
// "enterprise" by go-gh's definition, so its API lives at
// https://api.{tenant}.ghe.com/ with no /api/v3 segment.
func githubAPIPrefix(host string) string {
	hostname, port := splitHostPort(host)
	normalized := auth.NormalizeHostname(hostname)

	if auth.IsEnterprise(normalized) {
		if port != "" {
			return "https://" + net.JoinHostPort(normalized, port) + "/api/v3/"
		}
		return "https://" + normalized + "/api/v3/"
	}

	return "https://api." + normalized + "/"
}

// splitHostPort splits host[:port], returning an empty port when absent.
func splitHostPort(host string) (string, string) {
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		return host, ""
	}
	return hostname, port
}
