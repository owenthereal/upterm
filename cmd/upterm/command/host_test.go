package command

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func Test_validateShareRequiredFlags_readOnlyAndLocalTCPForwarding(t *testing.T) {
	origServer := flagServer
	origReadOnly := flagReadOnly
	origAllowLocalTCPForwarding := flagAllowLocalTCPForwarding
	t.Cleanup(func() {
		flagServer = origServer
		flagReadOnly = origReadOnly
		flagAllowLocalTCPForwarding = origAllowLocalTCPForwarding
	})

	flagServer = "ssh://uptermd.upterm.dev:22"

	cases := []struct {
		name                    string
		readOnly                bool
		allowLocalTCPForwarding bool
		wantErrSubstr           string
	}{
		{name: "neither", readOnly: false, allowLocalTCPForwarding: false},
		{name: "read-only only", readOnly: true, allowLocalTCPForwarding: false},
		{name: "forwarding only", readOnly: false, allowLocalTCPForwarding: true},
		{
			name:                    "both rejected",
			readOnly:                true,
			allowLocalTCPForwarding: true,
			wantErrSubstr:           "--read-only and --allow-local-tcp-forwarding cannot be used together",
		},
	}

	for _, c := range cases {
		cc := c
		t.Run(cc.name, func(t *testing.T) {
			flagReadOnly = cc.readOnly
			flagAllowLocalTCPForwarding = cc.allowLocalTCPForwarding

			err := validateShareRequiredFlags(nil, nil)
			if cc.wantErrSubstr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, cc.wantErrSubstr)
		})
	}
}

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
			url:        "wss://foo.com",
			wantScheme: "wss",
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
