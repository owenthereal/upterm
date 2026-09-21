//go:build windows

package command

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// daemonHandoffEnv is the variable whose presence makes this process the
// daemon on this platform: here, the socket it was told to call back on.
const daemonHandoffEnv = daemonSocketEnv

// daemonEnvCleared reports whether bootstrapConn removed every variable this
// transport hands a daemon, so the hosted command cannot inherit any of them
// — the nonce above all, which is a credential even once it has been spent.
func daemonEnvCleared() bool {
	return os.Getenv(daemonSocketEnv) == "" && os.Getenv(daemonNonceEnv) == "" && os.Getenv(daemonNameEnv) == ""
}

// reportPlatformFindings has little to add here, and says so.
//
// The Unix half's findings are all about a descriptor this transport never
// hands over: there is no close-on-exec flag on Windows, no session to lead,
// and no second copy of the parent's end to go looking for, because the child
// makes its own connection rather than inheriting one. What this transport
// needs instead — that a connection presenting the wrong nonce is refused,
// and that checking it leaves the rest of the exchange on the wire — is the
// listener's business rather than the child's, and is pinned in
// spawn_hello_test.go on every platform.
func reportPlatformFindings(report func(k, v string), _ net.Conn) {
	report("cloexec", "skipped: a Windows child inherits no handle on the parent's end to mark")
}

func requirePlatformReports(t *testing.T, log string) {
	t.Helper()
	require.Contains(t, log, "REPORT cloexec=skipped:")
	// eof is reported but not required: Winsock may report a peer that has
	// gone as a reset rather than a graceful close, and bootstrap.Child
	// treats either as the parent leaving. parent_gone, which the portable
	// half requires, is the contract.
	require.Regexp(t, `(?m)REPORT eof=(true|false)$`, log)

	// The door closes behind the child: spawnDaemon removes the launch
	// directory as soon as it has a connection. Nothing in the standard
	// library suggests this should fail — UnixListener.close unlinks before
	// it closes the fd, RemoveAll runs after that has returned, and the
	// accepted connection holds no handle on the path — but RemoveAll's error
	// is deliberately dropped, so a removal that stopped working would leave
	// one openable boot.sock per invocation and say nothing. This is the
	// assertion that would notice.
	m := regexp.MustCompile(`(?m)^REPORT handoff=(.+)$`).FindStringSubmatch(log)
	require.Len(t, m, 2, "the child did not report the socket it was told to dial")
	require.NoDirExists(t, filepath.Dir(m[1]),
		"the launch directory outlived the spawn: %s is still bindable", m[1])
}
