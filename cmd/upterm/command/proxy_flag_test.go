package command

import (
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
		{in: "http:user:s3cret@proxy.example.com", wantErr: "missing host"},
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
