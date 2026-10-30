package internal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGuestCommandSelection(t *testing.T) {
	for _, kind := range []string{"shell", "exec"} {
		for _, raw := range []string{"", `printf '%s' "a b|$x"`} {
			for _, choice := range []string{"neither", "login", "force"} {
				for _, readonly := range []bool{false, true} {
					for _, disabled := range []bool{false, true} {
						for _, pty := range []bool{false, true} {
							t.Run(fmt.Sprintf("%s/raw=%q/%s/readonly=%t/no-exec=%t/pty=%t", kind, raw, choice, readonly, disabled, pty), func(t *testing.T) {
								p := guestCommandPolicy{ReadOnly: readonly, ExecDisabled: disabled}
								if choice == "login" {
									p.LoginCommand = []string{"login", "literal | $"}
								}
								if choice == "force" {
									p.ForceCommand = []string{"forced", "literal | $"}
								}
								got, err := selectGuestCommand(kind, raw, p)
								if kind == "exec" && (readonly || disabled) {
									require.Error(t, err)
									return
								}
								require.NoError(t, err)
								require.Equal(t, kind == "shell" && choice == "neither", got.Shared)
								require.Equal(t, kind == "exec" && choice != "force", got.NeedsExecConsent)
								require.Equal(t, kind == "exec" && choice == "force", got.ForcedExec)
								require.Equal(t, raw, got.RawCommand)
								switch {
								case choice == "force":
									require.Equal(t, p.ForceCommand, got.Argv)
								case kind == "shell" && choice == "login":
									require.Equal(t, p.LoginCommand, got.Argv)
								case kind == "exec":
									require.Equal(t, raw, got.Argv[len(got.Argv)-1])
								}
							})
						}
					}
				}
			}
		}
	}
	t.Run("SFTP and local host controls", func(t *testing.T) {
		for _, choice := range []string{"neither", "login", "force"} {
			shared, private, local := &guestHandlers{}, &guestHandlers{}, &guestHandlers{}
			h := &sessionHandler{kind: kindGuest, readonly: true, execDisabled: true, sharedGuests: shared, privateCommands: private, hostHandlers: local}
			if choice == "login" {
				h.loginCommand = []string{"chosen"}
			}
			if choice == "force" {
				h.forceCommand = []string{"chosen"}
			}
			require.Same(t, shared, h.guestTracker("subsystem"), choice)
			h.kind = kindHost
			for _, request := range []string{"shell", "exec", "subsystem"} {
				require.Same(t, local, h.guestTracker(request), choice+"/"+request)
			}
		}
	})
	for _, kind := range []string{"subsystem", "unknown", ""} {
		_, err := selectGuestCommand(kind, "", guestCommandPolicy{})
		require.Error(t, err)
	}
}
