package internal

import (
	"testing"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/assert"
)

func TestGuestConnectionEnv(t *testing.T) {
	for _, tc := range []struct {
		name         string
		auth         *server.AuthRequest
		hideClientIP bool
		want         []string
	}{
		{
			name: "IPv4",
			auth: &server.AuthRequest{RemoteAddr: "203.0.113.7:51234", LocalAddr: "198.51.100.1:22"},
			want: []string{"SSH_CONNECTION=203.0.113.7 51234 198.51.100.1 22", "SSH_CLIENT=203.0.113.7 51234 22"},
		},
		{
			// sshd writes an IPv6 address bare, without the brackets a
			// host:port needs.
			name: "IPv6",
			auth: &server.AuthRequest{RemoteAddr: "[2001:db8::7]:51234", LocalAddr: "[2001:db8::1]:22"},
			want: []string{"SSH_CONNECTION=2001:db8::7 51234 2001:db8::1 22", "SSH_CLIENT=2001:db8::7 51234 22"},
		},
		{
			// A dual-stack listener reports IPv4 peers in mapped form; sshd
			// writes them as the IPv4 addresses they are.
			name: "IPv4-mapped IPv6",
			auth: &server.AuthRequest{RemoteAddr: "[::ffff:203.0.113.7]:51234", LocalAddr: "[::ffff:198.51.100.1]:22"},
			want: []string{"SSH_CONNECTION=203.0.113.7 51234 198.51.100.1 22", "SSH_CLIENT=203.0.113.7 51234 22"},
		},
		{
			name:         "client IP hidden",
			auth:         &server.AuthRequest{RemoteAddr: "203.0.113.7:51234", LocalAddr: "198.51.100.1:22"},
			hideClientIP: true,
		},
		{
			// A relay that predates local_addr: half an SSH_CONNECTION would
			// be a false one.
			name: "no relay end",
			auth: &server.AuthRequest{RemoteAddr: "203.0.113.7:51234"},
		},
		{
			name: "no guest end",
			auth: &server.AuthRequest{LocalAddr: "198.51.100.1:22"},
		},
		{
			// What an in-memory or unix listener reports.
			name: "not an IP address",
			auth: &server.AuthRequest{RemoteAddr: "pipe", LocalAddr: "198.51.100.1:22"},
		},
		{
			name: "no auth request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, guestConnectionEnv(tc.auth, tc.hideClientIP))
		})
	}
}
