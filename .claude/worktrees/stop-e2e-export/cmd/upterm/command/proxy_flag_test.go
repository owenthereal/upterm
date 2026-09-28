package command

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProxyURL(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		wantErr string
		// wantAbsent is checked on top of the default "s3cret". The percent
		// rows need it because url.EscapeError quotes only the three
		// characters around the escape, which is a fragment of the password
		// rather than the whole of it.
		wantAbsent []string
	}{
		{in: "", want: ""},
		{in: "http://proxy.example.com:3128", want: "http://proxy.example.com:3128"},
		// A missing port is filled in here so that every dial path agrees.
		// "proxy.example.com:" parses with an empty port and used to reach the
		// dialer intact, where it resolved as port 0.
		{in: "http://user:pass@proxy.example.com", want: "http://user:pass@proxy.example.com:80"},
		{in: "http://proxy.example.com:", want: "http://proxy.example.com:80"},
		{in: "http://[::1]", want: "http://[::1]:80"},
		{in: "http://[::1]:3128", want: "http://[::1]:3128"},
		{in: "https://proxy.example.com:3128", wantErr: "only http:// proxies are supported"},
		{in: "socks5://proxy.example.com:1080", wantErr: "only http:// proxies are supported"},
		{in: "proxy.example.com:3128", wantErr: "only http:// proxies are supported"},
		{in: "http://:3128", wantErr: "missing host"},
		{in: "https://user:s3cret@proxy.example.com", wantErr: "only http:// proxies are supported"},
		{in: "http://user:s3cret@:3128", wantErr: "missing host"},
		{in: "http://user:s3cret@proxy.example.com:port", wantErr: "not a valid URL"},
		{in: "user:s3cret@proxy.example.com:3128", wantErr: "only http:// proxies are supported"},
		// No "://" at all, so these never reach url.Parse. An IP written
		// without a scheme used to fail parsing and get a vaguer answer than
		// the identical mistake spelled with a hostname.
		{in: "http:user:s3cret@proxy.example.com", wantErr: "only http:// proxies are supported"},
		{in: "10.0.0.1:3128", wantErr: "only http:// proxies are supported"},
		{in: "[::1]:3128", wantErr: "only http:// proxies are supported"},
		{in: "localhost:3128", wantErr: "only http:// proxies are supported"},
		// A password holding any of these ends the authority early, so
		// url.Parse reports the password itself as a bad port or a bad escape.
		// These rows are what keeps the no-quoting promise honest.
		{in: "http://user:s3cret/x@proxy.example.com:3128", wantErr: "not a valid URL"},
		{in: "http://user:s3cret?x@proxy.example.com:3128", wantErr: "not a valid URL"},
		{in: "http://user:s3cret#x@proxy.example.com:3128", wantErr: "not a valid URL"},
		{in: "http://user:%s3cret@proxy.example.com:3128", wantErr: "percent-encoding", wantAbsent: []string{"%s3"}},
		{in: "http://user:50%off@proxy.example.com:3128", wantErr: "percent-encoding", wantAbsent: []string{"%of"}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseProxyURL(tc.in)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				for _, secret := range append([]string{"s3cret"}, tc.wantAbsent...) {
					assert.NotContains(t, err.Error(), secret)
				}
				return
			}
			require.NoError(t, err)
			if tc.want == "" {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tc.want, got.String())
		})
	}
}

// A rejected --proxy names its possible origins, because the value itself is
// withheld: without this, a bad UPTERM_PROXY or config entry reports neither
// what was wrong with it nor where it came from.
func TestParseProxyURLErrorsNameTheirOrigins(t *testing.T) {
	for _, in := range []string{
		"https://proxy.example.com:3128",
		"10.0.0.1:3128",
		"http://:3128",
		"http://user:s3cret@proxy.example.com:port",
	} {
		t.Run(in, func(t *testing.T) {
			_, err := parseProxyURL(in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "UPTERM_PROXY")
			assert.Contains(t, err.Error(), "proxy key in the config file")
		})
	}
}

// The host-key prompt is handed the socket's peer, which through a tunnel is
// the proxy. Whether that will happen is knowable only here, before the dial.
func TestConnectionIsProxied(t *testing.T) {
	envProxy, _ := url.Parse("http://proxy.example.com:3128")

	for _, tc := range []struct {
		name   string
		server string
		proxy  string
		// envAnswer is what the environment lookup returns; nil stands for
		// "no proxy applies", which is also how a NO_PROXY match arrives.
		envAnswer *url.URL
		envErr    error
		want      bool
		// wantProbe is the scheme the lookup must be asked about, since that
		// is what chooses between HTTP_PROXY and HTTPS_PROXY. Empty means the
		// environment must not be consulted at all.
		wantProbe string
	}{
		{name: "direct ssh", server: "ssh://uptermd.upterm.dev:22", envAnswer: envProxy, want: false},
		{name: "ssh with --proxy", server: "ssh://uptermd.upterm.dev:22", proxy: "http://proxy.example.com:3128", want: true},
		{name: "wss with --proxy", server: "wss://uptermd.upterm.dev:443", proxy: "http://proxy.example.com:3128", want: true},
		{name: "wss asks about https", server: "wss://uptermd.upterm.dev:443", envAnswer: envProxy, want: true, wantProbe: "https"},
		{name: "ws asks about http", server: "ws://uptermd.upterm.dev:80", envAnswer: envProxy, want: true, wantProbe: "http"},
		{name: "no proxy applies", server: "wss://uptermd.upterm.dev:443", want: false, wantProbe: "https"},
		{name: "a lookup error is not a proxy", server: "wss://uptermd.upterm.dev:443", envAnswer: envProxy, envErr: errors.New("bad"), want: false, wantProbe: "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probed string
			orig := proxyFromEnvironment
			proxyFromEnvironment = func(req *http.Request) (*url.URL, error) {
				probed = req.URL.Scheme
				return tc.envAnswer, tc.envErr
			}
			t.Cleanup(func() { proxyFromEnvironment = orig })

			var proxyURL *url.URL
			if tc.proxy != "" {
				var err error
				proxyURL, err = parseProxyURL(tc.proxy)
				require.NoError(t, err)
			}

			assert.Equal(t, tc.want, connectionIsProxied(tc.server, proxyURL))
			assert.Equal(t, tc.wantProbe, probed, "scheme the environment was asked about")
		})
	}
}
