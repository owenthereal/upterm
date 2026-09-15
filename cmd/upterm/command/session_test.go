package command

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/host/api"
	"github.com/stretchr/testify/require"
)

func TestBuildSessionDetailSSH(t *testing.T) {
	for _, tt := range []struct {
		host string
		want string
	}{
		{"ssh://example.com:22", "ssh sid@example.com"},
		{"ssh://example.com:2222", "ssh sid@example.com -p 2222"},
	} {
		t.Run(tt.host, func(t *testing.T) {
			detail, err := buildSessionDetail(&api.GetSessionResponse{Host: tt.host, SshUser: "sid"})
			require.NoError(t, err)
			require.Equal(t, tt.want, detail.SSHCommand)
		})
	}
}

func TestBuildSessionDetailWebSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a POSIX shell and OpenSSH")
	}
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is not installed")
	}

	const embeddedUser = "sid:MTI3LjAuMC4xOjIyMjI="
	for _, shellName := range []string{"sh", "bash", "zsh"} {
		t.Run(shellName, func(t *testing.T) {
			shell, err := exec.LookPath(shellName)
			if err != nil {
				t.Skipf("%s is not installed", shellName)
			}
			for _, tt := range []struct {
				name   string
				server string
				user   string
				want   string
			}{
				{"root", "ws://example.com:80", "sid", "ws://sid@example.com:80"},
				{"subpath", "wss://example.com/ws-uptermd/", "sid", "wss://sid@example.com/ws-uptermd/"},
				{"non-default port", "ws://example.com:8080/ws", "sid", "ws://sid@example.com:8080/ws"},
				{"ws on 443", "ws://example.com:443/ws", "sid", "ws://sid@example.com:443/ws"},
				{"wss on 80", "wss://example.com:80/ws", "sid", "wss://sid@example.com:80/ws"},
				{"escaped path", "wss://example.com/a%2Fb/team%20space/%25", "sid", "wss://sid@example.com/a%2Fb/team%20space/%25"},
				{"apostrophe", "wss://example.com/team's/session", "sid", "wss://sid@example.com/team's/session"},
				{"query", "wss://example.com/ws?a=1&b=2", "sid", "wss://sid@example.com/ws?a=1&b=2"},
				{"shell expansion", "wss://example.com/ws?x=$UPTERM_TEST_LITERAL&y=$(printf expanded)&z=`printf expanded`&q=\"'", "sid", "wss://sid@example.com/ws?x=$UPTERM_TEST_LITERAL&y=$(printf expanded)&z=`printf expanded`&q=\"'"},
				{"ssh tokens", "wss://example.com/ws?q=%h%p%r%n%%", "sid", "wss://sid@example.com/ws?q=%h%p%r%n%%"},
				{"embedded routing", "wss://example.com:443/ws", embeddedUser, "wss://" + embeddedUser + "@example.com:443/ws"},
				{"legacy routing", "wss://example.com:443/ws", "", "wss://" + embeddedUser + "@example.com:443/ws"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					detail, err := buildSessionDetail(&api.GetSessionResponse{
						Host: tt.server, SshUser: tt.user, SessionId: "sid", NodeAddr: "127.0.0.1:2222",
					})
					require.NoError(t, err)
					require.Equal(t, []string{"proxy", tt.want}, captureProxyArgs(t, shell, ssh, detail.SSHCommand))
				})
			}
		})
	}
}

// Run the displayed command through a real outer shell, OpenSSH's percent
// expansion, and its proxy shell. The stand-in upterm records argv and exits;
// no network connection or SSH server is needed.
func captureProxyArgs(t *testing.T, shell, ssh, command string) []string {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "upterm"), []byte("#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$UPTERM_TEST_ARGS\"\n"), 0o700))
	require.True(t, strings.HasPrefix(command, "ssh "))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-c",
		`exec "$UPTERM_TEST_SSH" -F /dev/null -o BatchMode=yes -o IdentityAgent=none -o IdentityFile=none `+strings.TrimPrefix(command, "ssh "))
	cmd.Env = append(os.Environ(),
		"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"SHELL="+shell, "UPTERM_TEST_SSH="+ssh, "UPTERM_TEST_ARGS="+argsFile, "UPTERM_TEST_LITERAL=expanded")
	output, err := cmd.CombinedOutput()
	require.Error(t, err, "the proxy exits without an SSH handshake")
	require.NoError(t, ctx.Err(), "SSH timed out: %s", output)
	args, err := os.ReadFile(argsFile)
	require.NoError(t, err, "command: %s\nSSH output: %s", command, output)
	return strings.Split(strings.TrimSuffix(string(args), "\x00"), "\x00")
}
