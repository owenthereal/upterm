package command

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/owenthereal/upterm/internal/testhelpers/testauthority"
	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
)

// authorityExtension composes a test authority, enabled or dark.
func authorityExtension(enabled bool) *Extension {
	return &Extension{Name: "probe", New: func(context.Context, Config) (server.Extensions, error) {
		return server.Extensions{Authority: testauthority.New(), Enabled: enabled, Protocols: []string{"test_v1"}}, nil
	}}
}

// An enabled authority's listener prerequisites are the command's to check,
// after New and before anything listens: whichever are missing, the first is
// named. A dark authority needs neither. Each run that passes them stops at
// the configuration's own refusal, a Consul routing with no Consul URL, so
// nothing listens.
func TestCommandPrerequisitesNameWhatIsMissing(t *testing.T) {
	prerequisites := []struct {
		flag    string
		missing string
	}{
		{"--ssh-network=tcp4", "uptermd: an enabled authority needs --ssh-network tcp4"},
		{"--ssh-proxy-protocol-required", "uptermd: an enabled authority needs --ssh-proxy-protocol-required"},
	}
	const later = "consul-url is required for consul routing mode"
	for _, enabled := range []bool{true, false} {
		for given := 0; given < 1<<len(prerequisites); given++ {
			want := later
			args := []string{"--routing", "consul"}
			for i, p := range prerequisites {
				if given&(1<<i) != 0 {
					args = append(args, p.flag)
				} else if enabled && want == later {
					want = p.missing
				}
			}
			t.Run(map[bool]string{true: "enabled", false: "dark"}[enabled]+"/"+want, func(t *testing.T) {
				resetUptermdEnv(t)
				addr, internal := freeAddr(t), freeAddr(t)
				err := execute(context.Background(), RootWith(authorityExtension(enabled)), append(args, "--ssh-addr", addr, "--internal-addr", internal)...)
				require.ErrorContains(t, err, want)
				if want != later {
					require.EqualError(t, err, want)
				}
				requireRefused(t, addr)
				requireRefused(t, internal)
			})
		}
	}
}

// startFailing is a Lifecycle whose Start fails with err.
type startFailing struct {
	err     error
	started int
	stopped int
}

func (l *startFailing) Start(context.Context, server.Runtime) error { l.started++; return l.err }
func (l *startFailing) Stop()                                       { l.stopped++ }

// A Lifecycle that fails to start stops uptermd before it accepts anything,
// and uptermd names the extension.
func TestLifecycleStartFailureNamesTheExtension(t *testing.T) {
	resetUptermdEnv(t)
	addr := freeAddr(t)
	boom := errors.New("boom")
	lifecycle := &startFailing{err: boom}
	cmd := RootWith(&Extension{Name: "probe", New: func(context.Context, Config) (server.Extensions, error) {
		return server.Extensions{Lifecycle: lifecycle}, nil
	}})
	err := execute(context.Background(), cmd, "--ssh-addr", addr, "--network", "mem")
	require.EqualError(t, err, "uptermd: extension probe: boom")
	require.ErrorIs(t, err, boom)
	require.Equal(t, 1, lifecycle.started)
	require.Equal(t, 1, lifecycle.stopped)
	requireRefused(t, addr)
}

// endsOnStart is a Lifecycle that ends its run once it has started, keeping
// the address of the relay whose Runtime it was given.
type endsOnStart struct {
	end      context.CancelFunc
	nodeAddr string
	started  int
	stopped  int
}

func (l *endsOnStart) Start(_ context.Context, rt server.Runtime) error {
	l.started++
	_, _, l.nodeAddr = rt.Identity()
	l.end()
	return nil
}

func (l *endsOnStart) Stop() { l.stopped++ }

// A composed uptermd starts its extension's Lifecycle on the relay it serves
// and, when its run ends cleanly, stops it before returning.
func TestLifecycleStartsAndStopsWithACleanRun(t *testing.T) {
	resetUptermdEnv(t)
	addr := freeAddr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lifecycle := &endsOnStart{end: cancel}
	cmd := RootWith(&Extension{Name: "probe", New: func(context.Context, Config) (server.Extensions, error) {
		return server.Extensions{Lifecycle: lifecycle}, nil
	}})
	require.NoError(t, execute(ctx, cmd, "--ssh-addr", addr, "--network", "mem"))
	require.Equal(t, 1, lifecycle.started, "the extension's Lifecycle was not started")
	require.Equal(t, addr, lifecycle.nodeAddr, "the Lifecycle was not given the serving relay's Runtime")
	require.Equal(t, 1, lifecycle.stopped, "the extension's Lifecycle was not stopped before the run returned")
	requireRefused(t, addr)
}
