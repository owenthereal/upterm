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
	}{
		{in: "", want: ""},
		{in: "http://proxy.example.com:3128", want: "http://proxy.example.com:3128"},
		{in: "http://user:pass@proxy.example.com", want: "http://user:pass@proxy.example.com"},
		{in: "https://proxy.example.com:3128", wantErr: "only http:// proxies are supported"},
		{in: "socks5://proxy.example.com:1080", wantErr: "only http:// proxies are supported"},
		{in: "proxy.example.com:3128", wantErr: "only http:// proxies are supported"},
		{in: "http://:3128", wantErr: "missing host"},
		{in: "https://user:s3cret@proxy.example.com", wantErr: "only http:// proxies are supported"},
		{in: "http://user:s3cret@:3128", wantErr: "missing host"},
		{in: "http://user:s3cret@proxy.example.com:port", wantErr: "invalid port"},
		{in: "user:s3cret@proxy.example.com:3128", wantErr: "only http:// proxies are supported"},
		{in: "http:user:s3cret@proxy.example.com", wantErr: "missing host"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseProxyURL(tc.in)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				assert.NotContains(t, err.Error(), "s3cret")
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
