package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owenthereal/upterm/cmd/upterm/command/internal/bootstrap"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/internal/testhelpers/fakerelay"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// serverGrants is the guest policy of the Host the daemon builds: the fields
// the session's server enforces it with. SFTPWithoutApproval is what the
// server's file transfers run with, which Run grants for AutoAccept as well
// as for SFTPAutoAccept.
type serverGrants struct {
	AcceptExec, ExecDisabled                                                bool
	AllowLoopbackTCPForwarding, AllowLocalTCPForwarding, ForwardingDisabled bool
	ReadOnly, SFTPDisabled, SFTPWithoutApproval                             bool
	AutoAccept, FileTransferApprovalRequired, TerminalConsent               bool
}

// reportedGrants is what `session info -o json`, and `upterm host --detach
// -o json`, say guests may do: the keys a script reads.
type reportedGrants struct {
	Open                         bool   `json:"open"`
	Access                       string `json:"access"`
	StartConfirmed               bool   `json:"startConfirmed"`
	ReadOnly                     bool   `json:"readOnly"`
	FileTransfer                 string `json:"fileTransfer"`
	FileTransferApprovalRequired bool   `json:"fileTransferApprovalRequired"`
	LocalForwarding              bool   `json:"localForwarding"`
	GuestShell                   string `json:"guestShell"`
	Execution                    string `json:"execution"`
	TCPForwarding                string `json:"tcpForwarding"`
	ApprovalMethod               string `json:"approvalMethod"`
}

// reportedKeys are the keys of reportedGrants that every session's JSON
// carries; open is left out while it is false.
var reportedKeys = []string{"access", "startConfirmed", "readOnly", "fileTransfer", "fileTransferApprovalRequired",
	"localForwarding", "guestShell", "execution", "tcpForwarding", "approvalMethod"}

// guestKeysFile is an authorized_keys file holding one key, for the grants
// that need an allowlist.
func guestKeysFile(t *testing.T) string {
	t.Helper()
	key, err := host.NewHostKey()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(key.PublicKey()), 0o600))
	return path
}

// hostedSession hosts a session on relay with the host flags args, the
// config file config and the variables env, as the daemon does, up to the
// moment the relay has created it, and returns the Host the daemon built and
// the session it reported created. The config file and the variables set the
// flags as the root's pre-run has them do; the environment the test runs in
// sets none. stdin answers whatever the daemon asks the operator, such as
// the relay's host key; nil answers nothing.
func hostedSession(t *testing.T, relay *fakerelay.Relay, stdin io.Reader, config string, env map[string]string, args ...string) (*host.Host, *api.GetSessionResponse) {
	t.Helper()
	cmd := hostCmd()
	t.Cleanup(func() { hostCmd() })
	cmd.SetErr(io.Discard)
	daemonTestRoots(t)
	withConfig(t, config)

	require.NoError(t, cmd.ParseFlags(append([]string{"--server", "ssh://" + relay.Addr}, args...)))
	// The variables are env's alone. Every other one the binding reads is
	// unset, not emptied, since an empty variable is a value too: the
	// developer's own UPTERM_KNOWN_HOSTS, UPTERM_PRIVATE_KEY or
	// UPTERM_AUTHORIZED_USER would undo what daemonTestRoots keeps out.
	// After the parse, which merges host's flags into the set the binding
	// visits.
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		k := envVarName(f.Name)
		t.Setenv(k, "")
		require.NoError(t, os.Unsetenv(k))
	})
	for k, v := range env {
		t.Setenv(k, v)
	}
	// As the root's pre-run: what the command line set, and then the config
	// file and the environment, which set the rest.
	commandLine := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) { commandLine[f.Name] = true })
	supplied, _, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	suppliedFlags, commandLineFlags = supplied, commandLine
	require.NoError(t, validateShareRequiredFlags(cmd, nil))
	opts, err := parseHostOptions([]string{"sh"})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	created := make(chan *api.GetSessionResponse, 1)
	parent := bootstrap.NewParent(b, stdin, io.Discard, nil)
	parentDone := make(chan error, 1)
	go func() {
		_, err := parent.Run(ctx, bootstrap.Handlers{
			SessionCreated: func(s *api.GetSessionResponse) api.Accept_Decision {
				created <- s
				return api.Accept_DECLINED
			},
		})
		parentDone <- err
	}()
	child := bootstrap.NewChild(a, nil)
	h, err := buildDaemonHost(ctx, hostSettingsFromFlags(), "grants", opts, child, discardLogger())
	require.NoError(t, err)
	require.ErrorAs(t, h.Run(ctx), new(UserDiscardedError))
	require.NoError(t, child.Close())
	require.ErrorIs(t, <-parentDone, bootstrap.ErrDaemonGone)
	return h, <-created
}

// grantsOf is grantsWith, with an empty config file and no variables.
func grantsOf(t *testing.T, args ...string) (serverGrants, reportedGrants) {
	t.Helper()
	return grantsWith(t, "", nil, args...)
}

// grantsWith hosts a session with the host flags args, the config file
// config and the variables env, as the daemon does, up to the moment the
// relay has created it, and returns the policy the Host enforces and the
// policy the session reports. The config file and the variables set the
// flags as the root's pre-run has them do; the environment the test runs in
// sets none. The report is read as `session info` reads it: the JSON's keys,
// and the view's Guests row, which must say the same.
func grantsWith(t *testing.T, config string, env map[string]string, args ...string) (serverGrants, reportedGrants) {
	t.Helper()
	key, err := host.NewHostKey()
	require.NoError(t, err)
	relay := fakerelay.Start(t, key, fakerelay.RandomID)
	h, sess := hostedSession(t, relay, nil, config, env, append([]string{"--skip-host-key-check"}, args...)...)

	server := serverGrants{
		AcceptExec: h.AcceptExec, ExecDisabled: h.ExecDisabled,
		AllowLoopbackTCPForwarding: h.AllowLoopbackTCPForwarding, AllowLocalTCPForwarding: h.AllowLocalTCPForwarding,
		ForwardingDisabled: h.ForwardingDisabled,
		ReadOnly:           h.ReadOnly, SFTPDisabled: h.SFTPDisabled,
		SFTPWithoutApproval: h.AutoAccept || h.SFTPAutoAccept,
		AutoAccept:          h.AutoAccept, FileTransferApprovalRequired: h.FileTransferApprovalRequired,
		TerminalConsent: h.TerminalConsent,
	}

	info := withSessionReport(sessionInfo{}, sess)
	info.Open = sess.GetOpen()
	raw, err := json.Marshal(info)
	require.NoError(t, err)
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &keys))
	for _, k := range reportedKeys {
		require.Contains(t, keys, k, "the JSON has %s", k)
	}
	var reported reportedGrants
	require.NoError(t, json.Unmarshal(raw, &reported))

	view := guestPermissions(sess)
	require.NotNil(t, view, "session info's view has a Guests row")
	require.Equal(t, reported, reportedGrants{
		Open: reported.Open, Access: reported.Access, StartConfirmed: reported.StartConfirmed,
		ReadOnly: view.ReadOnly, FileTransfer: view.FileTransfer, FileTransferApprovalRequired: view.ApprovalRequired,
		LocalForwarding: view.LocalForwarding, GuestShell: *view.GuestShell, Execution: *view.Execution,
		TCPForwarding: *view.TCPForwarding, ApprovalMethod: *view.ApprovalMethod,
	}, "the view says what the JSON says")
	return server, reported
}

// asked is the policy with nothing granted and nothing turned off: the host
// was asked before the session started, and guests' commands, file transfers
// and loopback forwards wait for its approval in the terminal.
func asked() (serverGrants, reportedGrants) {
	return serverGrants{FileTransferApprovalRequired: true, TerminalConsent: true},
		reportedGrants{Access: "anyone", StartConfirmed: true, FileTransfer: "all", FileTransferApprovalRequired: true,
			GuestShell: "shared", Execution: "approval", TCPForwarding: "loopback-approval", ApprovalMethod: "terminal"}
}

// Each grant's spelling gives guests exactly what the host's policy says it
// does, at every layer: the Host's fields, and what session info reports.
func TestGuestGrantsReachTheSessionAsSpelled(t *testing.T) {
	keys := guestKeysFile(t)
	granted := func(s *serverGrants, r *reportedGrants) {
		s.SFTPWithoutApproval, s.FileTransferApprovalRequired = true, false
		r.FileTransferApprovalRequired = false
	}
	unasked := func(s *serverGrants, r *reportedGrants) {
		s.AutoAccept = true
		r.StartConfirmed = false
		granted(s, r)
	}
	for _, tc := range []struct {
		name string
		args []string
		edit func(*serverGrants, *reportedGrants)
	}{
		{"nothing granted", nil, func(*serverGrants, *reportedGrants) {}},
		{"commands", []string{"--allow-exec"}, func(s *serverGrants, r *reportedGrants) {
			s.AcceptExec, r.Execution = true, "granted"
		}},
		{"file transfers", []string{"--allow-sftp"}, granted},
		{"downloads", []string{"--read-only", "--allow-sftp"}, func(s *serverGrants, r *reportedGrants) {
			granted(s, r)
			s.ReadOnly, r.ReadOnly, r.FileTransfer, r.Execution, r.TCPForwarding = true, true, "downloads", "off", "off"
		}},
		{"loopback forwards", []string{"--allow-forwarding=loopback"}, func(s *serverGrants, r *reportedGrants) {
			s.AllowLoopbackTCPForwarding, r.TCPForwarding = true, "loopback"
		}},
		{"forwards anywhere", []string{"--allow-forwarding=any"}, func(s *serverGrants, r *reportedGrants) {
			s.AllowLocalTCPForwarding, r.TCPForwarding, r.LocalForwarding = true, "all", true
		}},
		{"forwards anywhere, by the old name", []string{"--allow-local-tcp-forwarding"}, func(s *serverGrants, r *reportedGrants) {
			s.AllowLocalTCPForwarding, r.TCPForwarding, r.LocalForwarding = true, "all", true
		}},
		{"forwards to loopback and anywhere", []string{"--allow-forwarding=loopback", "--allow-local-tcp-forwarding"}, func(s *serverGrants, r *reportedGrants) {
			s.AllowLoopbackTCPForwarding, s.AllowLocalTCPForwarding, r.TCPForwarding, r.LocalForwarding = true, true, "all", true
		}},
		{"started unasked", []string{"--accept"}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			r.Open = true
		}},
		{"in the background, asked", []string{"--detach"}, func(*serverGrants, *reportedGrants) {}},
		{"in the background, unasked", []string{"--detach", "--accept"}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			r.Open = true
		}},
		{"started unasked, no file transfer", []string{"--accept", "--no-sftp"}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			s.SFTPDisabled, r.Open, r.FileTransfer = true, true, "off"
		}},
		{"started unasked, read-only", []string{"--accept", "--read-only"}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			s.ReadOnly, r.Open, r.ReadOnly, r.FileTransfer = true, true, true, "downloads"
			r.Execution, r.TCPForwarding = "off", "off"
		}},
		{"nothing at all", []string{"--no-exec", "--no-forwarding"}, func(s *serverGrants, r *reportedGrants) {
			s.ExecDisabled, s.ForwardingDisabled, r.Execution, r.TCPForwarding = true, true, "off", "off"
		}},
		{"a CI session for VS Code", []string{"--accept", "--allow-exec", "--allow-forwarding=loopback", "--authorized-keys", keys}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			s.AcceptExec, s.AllowLoopbackTCPForwarding, r.Access, r.Execution, r.TCPForwarding = true, true, "allowlist", "granted", "loopback"
		}},
		{"a CI session forwarding anywhere", []string{"--accept", "--allow-exec", "--allow-forwarding=loopback", "--allow-local-tcp-forwarding", "--authorized-keys", keys}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			s.AcceptExec, s.AllowLoopbackTCPForwarding, s.AllowLocalTCPForwarding = true, true, true
			r.Access, r.Execution, r.TCPForwarding, r.LocalForwarding = "allowlist", "granted", "all", true
		}},
		{"full access", []string{"--full-access", "--authorized-keys", keys}, func(s *serverGrants, r *reportedGrants) {
			granted(s, r)
			s.AcceptExec, s.AllowLoopbackTCPForwarding, r.Access, r.Execution, r.TCPForwarding = true, true, "allowlist", "granted", "loopback"
		}},
		{"full access, forwarding anywhere", []string{"--full-access", "--allow-forwarding=any", "--authorized-keys", keys}, func(s *serverGrants, r *reportedGrants) {
			granted(s, r)
			s.AcceptExec, s.AllowLoopbackTCPForwarding, s.AllowLocalTCPForwarding = true, true, true
			r.Access, r.Execution, r.TCPForwarding, r.LocalForwarding = "allowlist", "granted", "all", true
		}},
		{"a CI session for VS Code, with full access", []string{"--accept", "--full-access", "--authorized-keys", keys}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			s.AcceptExec, s.AllowLoopbackTCPForwarding, r.Access, r.Execution, r.TCPForwarding = true, true, "allowlist", "granted", "loopback"
		}},
		{"a CI session forwarding anywhere, with full access", []string{"--accept", "--full-access", "--allow-forwarding=any", "--authorized-keys", keys}, func(s *serverGrants, r *reportedGrants) {
			unasked(s, r)
			s.AcceptExec, s.AllowLoopbackTCPForwarding, s.AllowLocalTCPForwarding = true, true, true
			r.Access, r.Execution, r.TCPForwarding, r.LocalForwarding = "allowlist", "granted", "all", true
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantServer, wantReported := asked()
			tc.edit(&wantServer, &wantReported)
			server, reported := grantsOf(t, tc.args...)
			require.Equal(t, wantServer, server, "the Host")
			require.Equal(t, wantReported, reported, "what session info reports")
		})
	}
}

// Spellings that mean the same grant give the session the same policy.
func TestGuestGrantSpellingsThatMeanTheSameAreTheSame(t *testing.T) {
	keys := guestKeysFile(t)
	allowlist := []string{"--authorized-keys", keys}
	for _, pair := range []struct {
		name string
		a, b []string
	}{
		{"forwards anywhere", []string{"--allow-local-tcp-forwarding"}, []string{"--allow-forwarding=any"}},
		{"started unasked", []string{"--accept"}, []string{"--accept", "--allow-sftp"}},
		{"full access", []string{"--full-access"}, []string{"--allow-exec", "--allow-sftp", "--allow-forwarding=loopback"}},
		{"full access, forwarding anywhere", []string{"--full-access", "--allow-forwarding=any"},
			[]string{"--allow-exec", "--allow-sftp", "--allow-forwarding=loopback", "--allow-local-tcp-forwarding"}},
		{"full access, started unasked", []string{"--accept", "--full-access"}, []string{"--accept", "--allow-exec", "--allow-forwarding=loopback"}},
	} {
		t.Run(pair.name, func(t *testing.T) {
			a, b := pair.a, pair.b
			if strings.HasPrefix(pair.name, "full access") {
				a, b = append(a, allowlist...), append(b, allowlist...)
			}
			server, reported := grantsOf(t, a...)
			sameServer, sameReported := grantsOf(t, b...)
			require.Equal(t, server, sameServer, "the Host")
			require.Equal(t, reported, sameReported, "what session info reports")
		})
	}
}

// A grant and a denial of the same thing on one command line contradict
// each other, and upterm says so rather than picking one.
func TestGuestGrantContradictionsOnTheCommandLineAreErrors(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--allow-exec", "--no-exec"}, "--allow-exec and --no-exec contradict each other; pick one"},
		{[]string{"--allow-sftp", "--no-sftp"}, "--allow-sftp and --no-sftp contradict each other; pick one"},
		{[]string{"--allow-forwarding=loopback", "--no-forwarding"}, "--allow-forwarding and --no-forwarding contradict each other; pick one"},
		{[]string{"--allow-forwarding=any", "--no-forwarding"}, "--allow-forwarding and --no-forwarding contradict each other; pick one"},
		{[]string{"--allow-local-tcp-forwarding", "--no-forwarding"}, "--allow-local-tcp-forwarding and --no-forwarding contradict each other; pick one"},
		{[]string{"--read-only", "--allow-exec"}, "--allow-exec and --read-only contradict each other; pick one"},
		{[]string{"--read-only", "--allow-forwarding=loopback"}, "--allow-forwarding and --read-only contradict each other; pick one"},
		{[]string{"--read-only", "--allow-local-tcp-forwarding"}, "--allow-local-tcp-forwarding and --read-only contradict each other; pick one"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			stdout, stderr, code := runCLI(t, append(append([]string{"host"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			require.Equal(t, oldNameNotice(tc.args)+"upterm: "+tc.want+"\n", stderr)
			require.Empty(t, stdout)
		})
	}

	// Each contradiction is a line of its own.
	setupSessionRoots(t)
	withConfig(t, "")
	_, stderr, code := runCLI(t, "host", "--read-only", "--allow-exec", "--no-exec", "--allow-forwarding=any", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: --allow-exec and --no-exec contradict each other; pick one\n"+
		"upterm: --allow-exec and --read-only contradict each other; pick one\n"+
		"upterm: --allow-forwarding and --read-only contradict each other; pick one\n", stderr)
}

// With one side from the environment or the config file, the denial wins:
// the session starts, and upterm says which grant has no effect and where
// the denial came from.
func TestGuestGrantContradictionsFromEnvOrConfigAreWarnings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config string
		env    string // UPTERM_READ_ONLY's value
		args   []string
		want   string // with %s for the config file
	}{
		{"read-only in config", "read-only: true\n", "", []string{"--allow-exec"},
			"upterm: --allow-exec has no effect: read-only (from %s) denies guest commands"},
		{"read-only in config, forwarding", "read-only: true\n", "", []string{"--allow-forwarding=loopback"},
			"upterm: --allow-forwarding has no effect: read-only (from %s) denies port forwarding"},
		{"read-only in config, forwarding by the old name", "read-only: true\n", "", []string{"--allow-local-tcp-forwarding"},
			"upterm: --allow-local-tcp-forwarding has no effect: read-only (from %s) denies port forwarding"},
		{"no-sftp in config", "no-sftp: true\n", "", []string{"--allow-sftp"},
			"upterm: --allow-sftp has no effect: no-sftp (from %s) denies file transfers"},
		{"forwarding in config, --no-forwarding", "allow-local-tcp-forwarding: true\n", "", []string{"--no-forwarding"},
			"upterm: allow-local-tcp-forwarding (from %s) has no effect: --no-forwarding denies port forwarding"},
		{"forwarding in config, --read-only", "allow-local-tcp-forwarding: true\n", "", []string{"--read-only"},
			"upterm: allow-local-tcp-forwarding (from %s) has no effect: --read-only denies port forwarding"},
		{"read-only in the environment", "", "true", []string{"--allow-exec"},
			"upterm: --allow-exec has no effect: read-only (from UPTERM_READ_ONLY) denies guest commands"},
		{"the environment over the config file", "read-only: false\n", "true", []string{"--allow-exec"},
			"upterm: --allow-exec has no effect: read-only (from UPTERM_READ_ONLY) denies guest commands"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			if tc.env != "" {
				t.Setenv("UPTERM_READ_ONLY", tc.env)
			}
			want := tc.want
			if strings.Contains(want, "%s") {
				want = fmt.Sprintf(want, utils.UptermConfigFilePath())
			}
			// A proxy that can't be parsed stops the run once validation has
			// passed: the warning didn't stop it.
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept", "--proxy", "://not-a-url"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			stderr, ok := strings.CutPrefix(stderr, oldNameNotice(tc.args))
			require.True(t, ok, stderr)
			lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
			require.Len(t, lines, 2, stderr)
			require.Equal(t, want, lines[0])
			require.Contains(t, lines[1], "proxy", "and the run went on to the proxy")
		})
	}
}

// A grant and a denial of the same thing, one of them from the environment
// or the config file, have the effect upterm's warning says: the grant has
// none. The Host is given both, and enforces the denial first, so what
// session info reports is the denial's.
func TestTheDenialWinsWithOneSideFromEnvOrConfig(t *testing.T) {
	readOnly := func(s *serverGrants, r *reportedGrants) {
		s.ReadOnly, r.ReadOnly, r.FileTransfer, r.Execution, r.TCPForwarding = true, true, "downloads", "off", "off"
	}
	for _, tc := range []struct {
		name   string
		config string
		env    map[string]string
		args   []string
		edit   func(*serverGrants, *reportedGrants)
	}{
		{name: "read-only in config, --allow-exec", config: "read-only: true\n", args: []string{"--allow-exec"},
			edit: func(s *serverGrants, r *reportedGrants) {
				s.AcceptExec = true
				readOnly(s, r)
			}},
		{name: "read-only in config, --allow-forwarding=any", config: "read-only: true\n", args: []string{"--allow-forwarding=any"},
			edit: func(s *serverGrants, r *reportedGrants) {
				s.AllowLocalTCPForwarding = true
				readOnly(s, r)
			}},
		{name: "read-only in the environment, --allow-exec", env: map[string]string{"UPTERM_READ_ONLY": "true"}, args: []string{"--allow-exec"},
			edit: func(s *serverGrants, r *reportedGrants) {
				s.AcceptExec = true
				readOnly(s, r)
			}},
		{name: "no-sftp in config, --allow-sftp", config: "no-sftp: true\n", args: []string{"--allow-sftp"},
			edit: func(s *serverGrants, r *reportedGrants) {
				s.SFTPDisabled, s.SFTPWithoutApproval, s.FileTransferApprovalRequired = true, true, false
				r.FileTransfer, r.FileTransferApprovalRequired = "off", false
			}},
		{name: "allow-local-tcp-forwarding in config, --read-only", config: "allow-local-tcp-forwarding: true\n", args: []string{"--read-only"},
			edit: func(s *serverGrants, r *reportedGrants) {
				s.AllowLocalTCPForwarding = true
				readOnly(s, r)
			}},
		{name: "allow-local-tcp-forwarding in config, --no-forwarding", config: "allow-local-tcp-forwarding: true\n", args: []string{"--no-forwarding"},
			edit: func(s *serverGrants, r *reportedGrants) {
				s.AllowLocalTCPForwarding, s.ForwardingDisabled, r.TCPForwarding = true, true, "off"
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantServer, wantReported := asked()
			tc.edit(&wantServer, &wantReported)
			server, reported := grantsWith(t, tc.config, tc.env, tc.args...)
			require.Equal(t, wantServer, server, "the Host")
			require.Equal(t, wantReported, reported, "what session info reports")
		})
	}
}

// A file that contradicts itself is the error it was before: neither side is
// this run's choice, and config edit says the same of it.
func TestAConfigFileThatContradictsItselfIsAnError(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "read-only: true\nallow-local-tcp-forwarding: true\n")
	_, stderr, code := runCLI(t, "host", "--accept", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, "upterm: --read-only and --allow-local-tcp-forwarding cannot be used together: a read-only session must not permit network pivoting through the host\n", stderr)
}

// The daemon runs the same checks on the same argv, env and config, and
// says nothing of them: its stderr is the log, and the parent has said it.
func TestGuestGrantWarningsAreTheParentsOnly(t *testing.T) {
	setupSessionRoots(t)
	withConfig(t, "read-only: true\n")
	// Refused by a check of its own, so the run ends before it would read
	// the daemon's channel.
	t.Setenv(daemonHandoffEnv, "x")
	_, stderr, code := runCLI(t, "host", "--accept", "--allow-exec", "--name", "a/b", "--", "true")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "a/b", "the checks ran")
	require.NotContains(t, stderr, "has no effect")
}

// What isn't a contradiction passes, and says nothing.
func TestGuestGrantsThatAgreePass(t *testing.T) {
	for _, args := range [][]string{
		{"--read-only", "--allow-sftp"},
		{"--accept", "--no-sftp"},
		{"--accept", "--allow-sftp"},
		{"--allow-forwarding=loopback", "--allow-local-tcp-forwarding"},
		{"--allow-exec", "--allow-sftp", "--allow-forwarding=any", "--no-sftp=false"},
		{"--no-exec", "--no-sftp", "--no-forwarding", "--read-only"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept", "--proxy", "://not-a-url"}, args...), "--", "true")...)
			require.Equal(t, 1, code)
			stderr, ok := strings.CutPrefix(stderr, oldNameNotice(args))
			require.True(t, ok, stderr)
			require.Equal(t, 1, strings.Count(stderr, "\n"), stderr)
			require.Contains(t, stderr, "proxy", "the run went on to the proxy")
		})
	}
}

// --allow-forwarding names which forwards it grants; nothing else is one.
func TestAllowForwardingIsLoopbackOrAny(t *testing.T) {
	for args, want := range map[string]string{
		"--allow-forwarding=local": `upterm: invalid argument "local" for "--allow-forwarding" flag: must be loopback or any` + "\n",
		"--allow-forwarding=":      `upterm: invalid argument "" for "--allow-forwarding" flag: must be loopback or any` + "\n",
		"--allow-forwarding":       "upterm: flag needs an argument: --allow-forwarding\n",
	} {
		t.Run(args, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			_, stderr, code := runCLI(t, "host", args)
			require.Equal(t, 1, code)
			require.Equal(t, want, stderr)
		})
	}
	setupSessionRoots(t)
	withConfig(t, "")
	got, directive := complete(t, "host", "--allow-forwarding", "")
	require.Equal(t, []string{"loopback", "any"}, got)
	require.Equal(t, noFileComp, directive)
}

// The grant flags' earlier names, which no release had, are gone; the
// released --allow-local-tcp-forwarding stays, out of the help, as
// --allow-forwarding=any, from the command line and from the config file.
func TestTheGrantFlagsEarlierNames(t *testing.T) {
	for _, name := range []string{"accept-exec", "allow-loopback-tcp-forwarding"} {
		setupSessionRoots(t)
		withConfig(t, "")
		_, stderr, code := runCLI(t, "host", "--"+name)
		require.Equal(t, 1, code)
		require.Equal(t, "upterm: unknown flag: --"+name+"\n", stderr)
	}

	f := hostCmd().PersistentFlags().Lookup("allow-local-tcp-forwarding")
	require.NotNil(t, f)
	require.True(t, f.Hidden)
	setupSessionRoots(t)
	withConfig(t, "")
	stdout, _, code := runCLI(t, "host", "--help")
	require.Equal(t, 0, code)
	require.NotContains(t, stdout, "allow-local-tcp-forwarding")

	restoreFlags(t)
	withConfig(t, "allow-local-tcp-forwarding: true\n")
	cmd := hostCmdForBinding(t)
	_, deps, err := bindFlagsToEnv(cmd)
	require.NoError(t, err)
	require.Empty(t, deps, "a key config still sets")
	require.True(t, flagAllowLocalTCPForwarding)
}

// --full-access grants a shell as you, so it needs an allowlist, from any
// origin; and it asks for all of what it grants, so a denial of any of it,
// from any origin, refuses the run rather than narrowing it.
func TestFullAccessNeedsAnAllowlistAndNoDenial(t *testing.T) {
	keys := guestKeysFile(t)
	for _, tc := range []struct {
		name   string
		config string
		env    map[string]string
		args   []string
		want   string // with %s for the config file
	}{
		{name: "no allowlist", args: []string{"--full-access"},
			want: "upterm: --full-access needs --authorized-user or --authorized-keys: without one, anyone with the session ID would get a shell as you"},
		{name: "--no-exec", args: []string{"--full-access", "--authorized-keys", keys, "--no-exec"},
			want: "upterm: --full-access and --no-exec contradict each other; pick one"},
		{name: "--no-sftp", args: []string{"--full-access", "--authorized-keys", keys, "--no-sftp"},
			want: "upterm: --full-access and --no-sftp contradict each other; pick one"},
		{name: "--no-forwarding", args: []string{"--full-access", "--authorized-keys", keys, "--no-forwarding"},
			want: "upterm: --full-access and --no-forwarding contradict each other; pick one"},
		{name: "--read-only", args: []string{"--full-access", "--authorized-keys", keys, "--read-only"},
			want: "upterm: --full-access and --read-only contradict each other; pick one"},
		{name: "read-only in config", config: "read-only: true\n", args: []string{"--full-access", "--authorized-keys", keys},
			want: "upterm: --full-access and read-only (from %s) contradict each other; pick one"},
		{name: "no-sftp in the environment", env: map[string]string{"UPTERM_NO_SFTP": "true"}, args: []string{"--full-access", "--authorized-keys", keys},
			want: "upterm: --full-access and no-sftp (from UPTERM_NO_SFTP) contradict each other; pick one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			want := tc.want
			if strings.Contains(want, "%s") {
				want = fmt.Sprintf(want, utils.UptermConfigFilePath())
			}
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			require.Equal(t, want+"\n", stderr)
		})
	}

	// An allowlist from the config file is an allowlist, and forwarding
	// anywhere widens what --full-access grants rather than contradicting it.
	for name, tc := range map[string]struct {
		config string
		args   []string
	}{
		"an allowlist in config":  {"authorized-keys: " + keys + "\n", []string{"--full-access"}},
		"forwarding anywhere too": {"", []string{"--full-access", "--authorized-keys", keys, "--allow-forwarding=any"}},
	} {
		t.Run(name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept", "--proxy", "://not-a-url"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			require.Equal(t, 1, strings.Count(stderr, "\n"), stderr)
			require.Contains(t, stderr, "proxy", "the run went on to the proxy")
		})
	}
}

// --full-access's help says what an SSH login gets, and that it needs an
// allowlist; the description says it once among the grants.
func TestFullAccessHelp(t *testing.T) {
	host := findCommand(t, "upterm host")
	f := host.Flag("full-access")
	require.NotNil(t, f)
	require.Equal(t, "Let authorized guests do what an SSH login to your account can, without asking: "+
		"run commands (ssh SESSION CMD, VS Code, herdr --remote), transfer files (scp, sftp), "+
		"and forward ports to this machine's loopback addresses (ssh -L 8080:127.0.0.1:8080). "+
		"Requires --authorized-user or --authorized-keys.", f.Usage)
	require.Contains(t, oneSpaced(host.Long), "--full-access allows all three, for the keys --authorized-user or --authorized-keys names.")
}

// Each flag that grants guests something or denies it says exactly what it
// does, and the description's grant table and the paragraph under it, as
// they are laid out, say how the flags fit together.
func TestGuestGrantHelp(t *testing.T) {
	host := findCommand(t, "upterm host")
	for _, tc := range []struct{ name, usage string }{
		{"allow-exec", "Let guests run commands (ssh SESSION CMD, VS Code, herdr --remote) without approval. Each runs as you, and its stdin can carry further code."},
		{"allow-sftp", "Let guests transfer files (scp, sftp) without approval, with your access; downloads only with --read-only."},
		{"allow-forwarding", "Let guests forward ports (ssh -L) without approval: loopback, to this machine's literal 127.0.0.0/8 and ::1 addresses; any, to anything this machine can reach."},
		{"no-sftp", "Turn off file transfer (sftp and scp) for guests."},
		{"read-only", "Let guests only watch: they can't type into the session, run commands or forward ports, and can only download files."},
		{"no-exec", "Deny explicit guest exec requests, including forced exec. Host-chosen login and forced shell commands still run."},
		{"no-forwarding", "Deny guest TCP forwarding, including pregranted and approved destinations."},
		{"full-access", "Let authorized guests do what an SSH login to your account can, without asking: " +
			"run commands (ssh SESSION CMD, VS Code, herdr --remote), transfer files (scp, sftp), " +
			"and forward ports to this machine's loopback addresses (ssh -L 8080:127.0.0.1:8080). " +
			"Requires --authorized-user or --authorized-keys."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := host.Flag(tc.name)
			require.NotNil(t, f)
			require.Equal(t, tc.usage, f.Usage)
		})
	}

	const grants = `What guests can do: type into the session, or only watch it with
--read-only. A guest's plain ssh shares this terminal, or runs the program
--login-command names instead. Anything more needs a grant:
  commands     ssh SESSION CMD, VS Code, herdr --remote, run as you
               (--allow-exec, --no-exec)
  files        scp and sftp, with your access (--allow-sftp, --no-sftp)
  forwarding   ssh -L 8080:127.0.0.1:8080, to this machine's loopback
               addresses (--allow-forwarding=loopback, --no-forwarding)
--allow-X lets guests do X without asking, --no-X never lets them, and with
neither, upterm asks in your terminal. --full-access allows all three, for
the keys --authorized-user or --authorized-keys names. Forwards anywhere else
are refused unless --allow-forwarding=any, which lets guests reach anything
this machine can, without asking. --read-only also turns off commands,
uploads and forwarding.`
	require.Contains(t, host.Long, "\n\n"+grants+"\n\n", "a paragraph of its own")
}

// --detach asks its start question as upterm host does, on the terminal it
// was started from; with no terminal to ask in it needs --accept, and says
// that --accept grants file transfers too. It never implies consent.
func TestDetachAsksOnATerminalAndNeedsAcceptWithoutOne(t *testing.T) {
	const want = "upterm: --detach needs --accept when there is no terminal to ask in (it also lets guests transfer files without asking)\n"
	for _, args := range [][]string{
		{"host", "--detach", "--", "true"},
		{"host", "--detach", "-o", "json", "--", "true"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, "")
			// runCLI's stdin and stdout are pipes.
			stdout, stderr, code := runCLI(t, args...)
			require.Equal(t, 1, code)
			require.Equal(t, want, stderr)
			require.Empty(t, stdout)
		})
	}

	// The question is the terminal's to ask, so the checks every run makes,
	// the daemon's included, have nothing against --detach without --accept.
	cmd := hostCmd()
	defer hostCmd()
	require.NoError(t, cmd.ParseFlags([]string{"--detach"}))
	require.NoError(t, validateShareRequiredFlags(cmd, nil))
	require.NoError(t, cmd.ParseFlags([]string{"-o", "json"}))
	require.NoError(t, validateShareRequiredFlags(cmd, nil))
}

// --detach's help says when it asks, and what it needs when it can't.
func TestDetachHelpSaysWhenItAsks(t *testing.T) {
	host := findCommand(t, "upterm host")
	require.Equal(t, "Start the session in the background and exit once it is running. "+
		"On a terminal, upterm asks before starting it, as it does without --detach; with no terminal to ask in, pass --accept. "+
		"Attach a terminal later with 'upterm attach NAME'; stop it with 'upterm session stop NAME'.", host.Flag("detach").Usage)
	require.Contains(t, oneSpaced(host.Long), "With --detach nothing is attached: the session starts in the background, and upterm prints how to reach it. "+
		"It still asks before starting it, on this terminal; with no terminal to ask in, --detach needs --accept.")
}

// oldNameNotice is what host says first when its command line gives
// --allow-forwarding=any's released name, and "" when it doesn't.
func oldNameNotice(args []string) string {
	if slices.Contains(args, "--allow-local-tcp-forwarding") {
		return "upterm: --allow-local-tcp-forwarding is deprecated; use --allow-forwarding=any\n"
	}
	return ""
}

// --allow-local-tcp-forwarding on the command line is said to be deprecated,
// once, by the process that was given it. The config key and the variable
// aren't: they have no other spelling, since --allow-forwarding is the
// command line's only. Nor is --allow-local-tcp-forwarding=false, which only
// turns their grant off and has no other spelling either.
func TestAllowLocalTCPForwardingIsDeprecatedOnTheCommandLine(t *testing.T) {
	const notice = "upterm: --allow-local-tcp-forwarding is deprecated; use --allow-forwarding=any\n"
	for _, tc := range []struct {
		name, config, env string // env is UPTERM_ALLOW_LOCAL_TCP_FORWARDING's value
		args              []string
		notice            bool
	}{
		{name: "the command line", args: []string{"--allow-local-tcp-forwarding"}, notice: true},
		{name: "the config key", config: "allow-local-tcp-forwarding: true\n"},
		{name: "the variable", env: "true"},
		{name: "turned off on the command line", config: "allow-local-tcp-forwarding: true\n", args: []string{"--allow-local-tcp-forwarding=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			if tc.env != "" {
				t.Setenv("UPTERM_ALLOW_LOCAL_TCP_FORWARDING", tc.env)
			}
			// A proxy that can't be parsed stops the run once the checks have
			// passed.
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept", "--proxy", "://not-a-url"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			lines := strings.SplitAfter(strings.TrimSuffix(stderr, "\n"), "\n")
			if tc.notice {
				require.Len(t, lines, 2, stderr)
				require.Equal(t, notice, lines[0])
			} else {
				require.Len(t, lines, 1, stderr)
			}
			require.True(t, strings.HasPrefix(lines[len(lines)-1], "upterm: invalid --proxy"), stderr)
		})
	}

	// --detach's parent says it, once, before anything else it says.
	setupSessionRoots(t)
	withConfig(t, "")
	_, stderr, code := runCLI(t, "host", "--detach", "--allow-local-tcp-forwarding", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, notice+"upterm: --detach needs --accept when there is no terminal to ask in (it also lets guests transfer files without asking)\n", stderr)

	// Its daemon, which runs the same checks on the same argv, says nothing
	// of it: its stderr is the log. Refused by a check of its own, so the run
	// ends before it would read the daemon's channel.
	setupSessionRoots(t)
	withConfig(t, "")
	t.Setenv(daemonHandoffEnv, "x")
	_, stderr, code = runCLI(t, "host", "--detach", "--accept", "--allow-local-tcp-forwarding", "--name", "a/b", "--", "true")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "a/b", "the checks ran")
	require.NotContains(t, stderr, "deprecated")
}

// allow-local-tcp-forwarding from the environment or the config file lets
// guests forward to any destination, and a command line that asks for
// forwards to loopback addresses alone doesn't narrow it. upterm says so
// once, in the parent and not in the daemon it starts, naming where the
// value came from.
func TestAllowLocalTCPForwardingFromEnvOrConfigSaysItWidensLoopbackForwarding(t *testing.T) {
	keys := guestKeysFile(t)
	const (
		loopback = "upterm: --allow-forwarding=loopback has no effect: allow-local-tcp-forwarding (from %s) lets guests forward to any destination\n"
		full     = "upterm: --full-access doesn't keep forwarding to loopback addresses: allow-local-tcp-forwarding (from %s) lets guests forward to any destination\n"
		inConfig = "allow-local-tcp-forwarding: true\n"
		variable = "UPTERM_ALLOW_LOCAL_TCP_FORWARDING"
	)
	for _, tc := range []struct {
		name, config, env string // env is the variable's value
		args              []string
		want              string // with %s for where the value came from
	}{
		{name: "--allow-forwarding=loopback, the config key", config: inConfig, args: []string{"--allow-forwarding=loopback"}, want: loopback},
		{name: "--allow-forwarding=loopback, the variable", env: "true", args: []string{"--allow-forwarding=loopback"}, want: loopback},
		{name: "--full-access, the config key", config: inConfig, args: []string{"--full-access", "--authorized-keys", keys}, want: full},
		{name: "--full-access, the variable", env: "true", args: []string{"--full-access", "--authorized-keys", keys}, want: full},
		{name: "--full-access and --allow-forwarding=loopback", config: inConfig,
			args: []string{"--full-access", "--allow-forwarding=loopback", "--authorized-keys", keys}, want: loopback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			from := utils.UptermConfigFilePath()
			if tc.env != "" {
				t.Setenv(variable, tc.env)
				from = variable
			}
			// A proxy that can't be parsed stops the run once the checks have
			// passed: the warning didn't stop it.
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept", "--proxy", "://not-a-url"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			lines := strings.SplitAfter(strings.TrimSuffix(stderr, "\n"), "\n")
			require.Len(t, lines, 2, stderr)
			require.Equal(t, fmt.Sprintf(tc.want, from), lines[0])
			require.True(t, strings.HasPrefix(lines[1], "upterm: invalid --proxy"), stderr)
		})
	}

	// --detach's parent says it, once, before anything else it says.
	setupSessionRoots(t)
	withConfig(t, inConfig)
	_, stderr, code := runCLI(t, "host", "--detach", "--allow-forwarding=loopback", "--", "true")
	require.Equal(t, 1, code)
	require.Equal(t, fmt.Sprintf(loopback, utils.UptermConfigFilePath())+
		"upterm: --detach needs --accept when there is no terminal to ask in (it also lets guests transfer files without asking)\n", stderr)

	// Its daemon, which runs the same checks on the same argv, env and
	// config, says nothing of it: its stderr is the log. Refused by a check
	// of its own, so the run ends before it would read the daemon's channel.
	setupSessionRoots(t)
	withConfig(t, inConfig)
	t.Setenv(daemonHandoffEnv, "x")
	_, stderr, code = runCLI(t, "host", "--detach", "--accept", "--allow-forwarding=loopback", "--name", "a/b", "--", "true")
	require.Equal(t, 1, code)
	require.Contains(t, stderr, "a/b", "the checks ran")
	require.NotContains(t, stderr, "any destination")
}

// Where allow-local-tcp-forwarding from the environment or the config file
// widens nothing the command line asked for, upterm says nothing of it: the
// command line asks for no forwards, or for forwards anywhere itself, or
// gives the flag a value of its own; the variable turns the key off; or
// forwarding is off anyway.
func TestAllowLocalTCPForwardingFromEnvOrConfigIsQuietWhenItWidensNothing(t *testing.T) {
	keys := guestKeysFile(t)
	const (
		inConfig   = "allow-local-tcp-forwarding: true\n"
		deprecated = "upterm: --allow-local-tcp-forwarding is deprecated; use --allow-forwarding=any\n"
	)
	for _, tc := range []struct {
		name   string
		env    map[string]string
		args   []string
		before string // what stderr says before the proxy's error
	}{
		{name: "no forwards asked for"},
		{name: "--allow-forwarding=any", args: []string{"--allow-forwarding=any"}},
		{name: "--full-access --allow-forwarding=any", args: []string{"--full-access", "--allow-forwarding=any", "--authorized-keys", keys}},
		{name: "the flag on the command line", args: []string{"--allow-forwarding=loopback", "--allow-local-tcp-forwarding"}, before: deprecated},
		{name: "--full-access and the flag on the command line", args: []string{"--full-access", "--allow-local-tcp-forwarding", "--authorized-keys", keys}, before: deprecated},
		{name: "turned off on the command line", args: []string{"--allow-forwarding=loopback", "--allow-local-tcp-forwarding=false"}},
		{name: "turned off in the environment", env: map[string]string{"UPTERM_ALLOW_LOCAL_TCP_FORWARDING": "false"}, args: []string{"--allow-forwarding=loopback"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, inConfig)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			// A proxy that can't be parsed stops the run once the checks have
			// passed.
			_, stderr, code := runCLI(t, append(append([]string{"host", "--accept", "--proxy", "://not-a-url"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			rest, ok := strings.CutPrefix(stderr, tc.before)
			require.True(t, ok, stderr)
			require.True(t, strings.HasPrefix(rest, "upterm: invalid --proxy"), stderr)
			require.Equal(t, 1, strings.Count(rest, "\n"), stderr)
		})
	}

	// Forwarding is off, by --no-forwarding or read-only from any origin, and
	// the run is refused for it.
	for _, tc := range []struct {
		name   string
		config string
		env    map[string]string
		args   []string
		want   string // with %s for the config file
	}{
		{name: "--allow-forwarding=loopback --no-forwarding", config: inConfig, args: []string{"--allow-forwarding=loopback", "--no-forwarding"},
			want: "upterm: allow-local-tcp-forwarding (from %s) has no effect: --no-forwarding denies port forwarding\n" +
				"upterm: --allow-forwarding and --no-forwarding contradict each other; pick one\n"},
		{name: "--full-access --no-forwarding", config: inConfig, args: []string{"--full-access", "--no-forwarding", "--authorized-keys", keys},
			want: "upterm: allow-local-tcp-forwarding (from %s) has no effect: --no-forwarding denies port forwarding\n" +
				"upterm: --full-access and --no-forwarding contradict each other; pick one\n"},
		{name: "--allow-forwarding=loopback --read-only", config: inConfig, args: []string{"--allow-forwarding=loopback", "--read-only"},
			want: "upterm: allow-local-tcp-forwarding (from %s) has no effect: --read-only denies port forwarding\n" +
				"upterm: --allow-forwarding and --read-only contradict each other; pick one\n"},
		{name: "--allow-forwarding=loopback, read-only in config", config: "read-only: true\n" + inConfig, args: []string{"--allow-forwarding=loopback"},
			want: "upterm: --allow-forwarding has no effect: read-only (from %s) denies port forwarding\n" +
				"upterm: --read-only and --allow-local-tcp-forwarding cannot be used together: a read-only session must not permit network pivoting through the host\n"},
		{name: "--full-access, read-only in the environment", config: inConfig, env: map[string]string{"UPTERM_READ_ONLY": "true"},
			args: []string{"--full-access", "--authorized-keys", keys},
			want: "upterm: --full-access and read-only (from UPTERM_READ_ONLY) contradict each other; pick one\n" +
				"upterm: --read-only and --allow-local-tcp-forwarding cannot be used together: a read-only session must not permit network pivoting through the host\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupSessionRoots(t)
			withConfig(t, tc.config)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			want := tc.want
			if strings.Contains(want, "%s") {
				want = fmt.Sprintf(want, utils.UptermConfigFilePath())
			}
			stdout, stderr, code := runCLI(t, append(append([]string{"host", "--accept"}, tc.args...), "--", "true")...)
			require.Equal(t, 1, code)
			require.Equal(t, want, stderr)
			require.Empty(t, stdout)
		})
	}
}

// What upterm says of allow-local-tcp-forwarding from the environment or the
// config file changes nothing: guests still forward to any destination.
func TestAllowLocalTCPForwardingFromEnvOrConfigStillForwardsAnywhere(t *testing.T) {
	keys := guestKeysFile(t)
	const inConfig = "allow-local-tcp-forwarding: true\n"
	inEnv := map[string]string{"UPTERM_ALLOW_LOCAL_TCP_FORWARDING": "true"}
	loopback := func(s *serverGrants, r *reportedGrants) {
		s.AllowLoopbackTCPForwarding, s.AllowLocalTCPForwarding, r.TCPForwarding, r.LocalForwarding = true, true, "all", true
	}
	full := func(s *serverGrants, r *reportedGrants) {
		loopback(s, r)
		s.AcceptExec, s.SFTPWithoutApproval, s.FileTransferApprovalRequired = true, true, false
		r.Access, r.Execution, r.FileTransferApprovalRequired = "allowlist", "granted", false
	}
	for _, tc := range []struct {
		name   string
		config string
		env    map[string]string
		args   []string
		edit   func(*serverGrants, *reportedGrants)
	}{
		{name: "--allow-forwarding=loopback, the config key", config: inConfig, args: []string{"--allow-forwarding=loopback"}, edit: loopback},
		{name: "--allow-forwarding=loopback, the variable", env: inEnv, args: []string{"--allow-forwarding=loopback"}, edit: loopback},
		{name: "--full-access, the config key", config: inConfig, args: []string{"--full-access", "--authorized-keys", keys}, edit: full},
		{name: "--full-access, the variable", env: inEnv, args: []string{"--full-access", "--authorized-keys", keys}, edit: full},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantServer, wantReported := asked()
			tc.edit(&wantServer, &wantReported)
			server, reported := grantsWith(t, tc.config, tc.env, tc.args...)
			require.Equal(t, wantServer, server, "the Host")
			require.Equal(t, wantReported, reported, "what session info reports")
		})
	}
}
