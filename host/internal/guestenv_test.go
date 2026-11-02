package internal

import (
	"runtime"
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

// A guest's private command is told nothing the host inherited about where
// it runs: the ssh login it may have come in by, and the multiplexer pane it
// was started in, down to the Herdr session, workspace and tab that pane is
// in. Where a Herdr server listens, and where its binary is, is not where the
// host is, and stays.
func TestWithoutHostSessionVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin", "SSH_CONNECTION=10.0.0.1 1 10.0.0.2 22", "SSH_CLIENT=10.0.0.1 1 22", "SSH_TTY=/dev/ttys001", "SSH_ORIGINAL_COMMAND=old",
		"TMUX=/tmp/tmux-501/default,1,0", "TMUX_PANE=%1", "STY=1.ttys001.host", "ZELLIJ=0", "ZELLIJ_SESSION_NAME=work", "ZELLIJ_PANE_ID=3",
		"HERDR_ENV=1", "HERDR_PANE_ID=p1", "HERDR_SESSION=work", "HERDR_TAB_ID=t1", "HERDR_WORKSPACE_ID=w1",
		"HERDR_SOCKET_PATH=/tmp/herdr.sock", "HERDR_BIN_PATH=/opt/homebrew/bin/herdr", "TMUX_TMPDIR=/tmp", "TERM=xterm",
	}
	assert.Equal(t, []string{"PATH=/usr/bin", "HERDR_SOCKET_PATH=/tmp/herdr.sock", "HERDR_BIN_PATH=/opt/homebrew/bin/herdr", "TMUX_TMPDIR=/tmp", "TERM=xterm"}, withoutHostSessionVars(env))
	assert.Equal(t, "TMUX=/tmp/tmux-501/default,1,0", env[5], "the caller's environment is left as it was")
	if runtime.GOOS == "windows" {
		assert.Equal(t, []string{"Path=C:\\", "Herdr_Bin_Path=C:\\herdr.exe"}, withoutHostSessionVars([]string{
			"Path=C:\\", "tmux=x", "Herdr_Env=1", "ssh_tty=stale", "herdr_session=work", "Herdr_Tab_Id=t1", "herdr_workspace_id=w1", "Herdr_Bin_Path=C:\\herdr.exe",
		}))
	}
}

func TestGuestProcessEnvironment(t *testing.T) {
	empty := guestProcessEnvironment(nil, "", false)
	assert.NotNil(t, empty, "exec.Cmd must receive an explicitly empty environment")
	assert.Empty(t, empty)
	env := []string{"A=first", "SSH_TTY=old", "TERM=host", "A=last", "SSH_ORIGINAL_COMMAND=original"}
	assert.Equal(t, []string{"TERM=host", "A=last", "SSH_ORIGINAL_COMMAND=original"}, guestProcessEnvironment(env, "ignored", false))
	assert.Equal(t, []string{"A=last", "SSH_ORIGINAL_COMMAND=original", "TERM=guest"}, guestProcessEnvironment(env, "guest", true))
	if runtime.GOOS == "windows" {
		assert.Equal(t, []string{"=D:=other", "=C:=new", "PATH=new"}, guestProcessEnvironment([]string{"=C:=old", "=D:=other", "=C:=new", "Path=old", "PATH=new", "ssh_tty=stale"}, "", false))
	}
}
