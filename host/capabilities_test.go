package host

import (
	"fmt"
	"testing"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/stretchr/testify/require"
)

// What a delegated run tells its broker guests may ask the relay for is what
// the session reports its guests may do, for every guest policy: a shell
// always, commands unless execution is off, file transfers unless they are
// off, and forwarding unless it is off. So the relay never refuses what
// `session info` says is allowed.
func TestCapabilitiesMatchTheGuestPolicyReport(t *testing.T) {
	// Spelled out, so the rule is pinned apart from the report it follows.
	for _, tc := range []struct {
		name string
		p    internal.Permissions
		want []string
	}{
		{"the defaults", internal.Permissions{}, []string{"shell", "exec", "sftp", "direct-tcpip"}},
		{"no file transfers", internal.Permissions{SFTPDisabled: true}, []string{"shell", "exec", "direct-tcpip"}},
		{"no forwarding", internal.Permissions{ForwardingDisabled: true}, []string{"shell", "exec", "sftp"}},
		{"no commands", internal.Permissions{ExecDisabled: true}, []string{"shell", "sftp", "direct-tcpip"}},
		{"read only", internal.Permissions{ReadOnly: true}, []string{"shell", "sftp"}},
		{"any forwarding", internal.Permissions{AllowLocalTCPForwarding: true}, []string{"shell", "exec", "sftp", "direct-tcpip"}},
	} {
		require.Equal(t, tc.want, capabilitiesFor(tc.p), tc.name)
	}

	const inputs = 9
	for combo := range 1 << inputs {
		on := func(i int) bool { return combo&(1<<i) != 0 }
		p := internal.Permissions{
			ReadOnly:                   on(0),
			ExecDisabled:               on(1),
			AcceptExec:                 on(2),
			SFTPDisabled:               on(3),
			ForwardingDisabled:         on(4),
			AllowLocalTCPForwarding:    on(5),
			AllowLoopbackTCPForwarding: on(6),
		}
		r := &api.GetSessionResponse{}
		if on(7) {
			r.ForceCommand = []string{"top"}
		}
		if on(8) {
			r.LoginCommand = []string{"bash", "-l"}
		}
		p.Report(r)

		want := []string{"shell"}
		if r.GetExecution() != "off" {
			want = append(want, "exec")
		}
		if r.GetFileTransfer() != "off" {
			want = append(want, "sftp")
		}
		if r.GetTcpForwarding() != "off" {
			want = append(want, "direct-tcpip")
		}
		require.Equal(t, want, capabilitiesFor(p), fmt.Sprintf("%+v, force command %v, login command %v: execution %s, file transfer %s, forwarding %s",
			p, on(7), on(8), r.GetExecution(), r.GetFileTransfer(), r.GetTcpForwarding()))
	}
}
