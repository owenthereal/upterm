package command

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_parseURL(t *testing.T) {
	cases := []struct {
		name       string
		url        string
		wantScheme string
		wantHost   string
		wantPort   string
	}{
		{
			name:       "port 443",
			url:        "wss://foo.com:443",
			wantScheme: "wss",
			wantHost:   "foo.com",
			wantPort:   "443",
		},
		{
			name:       "port 80",
			url:        "http://foo.com:80",
			wantScheme: "http",
			wantHost:   "foo.com",
			wantPort:   "80",
		},
		{
			name:       "port 22",
			url:        "ssh://foo.com:22",
			wantScheme: "ssh",
			wantHost:   "foo.com",
			wantPort:   "22",
		},
		{
			name:       "no port",
			url:        "https://foo.com",
			wantScheme: "https",
			wantHost:   "foo.com",
			wantPort:   "443",
		},
	}

	for _, c := range cases {
		cc := c
		t.Run(cc.name, func(t *testing.T) {
			t.Parallel()

			_, scheme, host, port, err := parseURL(cc.url)
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(cc.wantScheme, scheme); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(cc.wantHost, host); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(cc.wantPort, port); diff != "" {
				t.Fatal(diff)
			}
		})
	}

}
