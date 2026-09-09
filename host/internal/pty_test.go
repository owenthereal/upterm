package internal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// exitCode decides what status the guest is told the command exited with, so
// getting it wrong is invisible locally and wrong on the wire.
func TestExitCode(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantExited bool
	}{
		{
			name:       "no error is a clean exit",
			err:        nil,
			wantCode:   0,
			wantExited: true,
		},
		{
			name:       "windows exit status",
			err:        &ExitError{Code: 3},
			wantCode:   3,
			wantExited: true,
		},
		{
			name:       "wrapped windows exit status",
			err:        errors.Join(errors.New("run group"), &ExitError{Code: 3}),
			wantCode:   3,
			wantExited: true,
		},
		{
			name:       "an error that is not an exit tells us nothing",
			err:        errors.New("GetExitCodeProcess failed"),
			wantCode:   0,
			wantExited: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, exited := exitCode(tt.err)
			assert.Equal(t, tt.wantExited, exited)
			assert.Equal(t, tt.wantCode, code)
		})
	}
}

// A Windows status with the high bit set is still a status.
//
// Unhandled exceptions look like 0xC0000005, and "exit -1" becomes 0xFFFFFFFF.
// On a 32-bit build these do not fit a positive int, so carrying them as one
// used to make exitCode report "did not exit" and the guest got a flat 1. The
// int is only a courier -- ssh.Session.Exit converts back to uint32 -- so the
// invariant that matters is what comes out the other side of that conversion.
func TestExitCodeKeepsHighWindowsStatuses(t *testing.T) {
	for _, status := range []uint32{0xC0000005, 0xFFFFFFFF, 0x80000003} {
		code, exited := exitCode(&ExitError{Code: status})
		assert.True(t, exited, "status %#x is an exit, not a signal", status)
		assert.Equal(t, status, uint32(code), "status %#x should survive the trip to the wire", status)
	}
}
