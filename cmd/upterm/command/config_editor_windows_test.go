//go:build windows

package command

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindowsEditorPathsKeepTheirBackslashes(t *testing.T) {
	args, err := editorArgs(`C:\Windows\notepad.exe`)
	require.NoError(t, err)
	require.Equal(t, []string{`C:\Windows\notepad.exe`}, args)
	args, err = editorArgs(`"C:\Program Files\Notepad++\notepad++.exe" -multiInst`)
	require.NoError(t, err)
	require.Equal(t, []string{`C:\Program Files\Notepad++\notepad++.exe`, "-multiInst"}, args)
}

// CommandLineToArgvW answers an empty command line with the running
// program's own path, which must never become the editor.
func TestWindowsBlankEditorNamesNothing(t *testing.T) {
	for _, s := range []string{"", " ", "\t "} {
		args, err := editorArgs(s)
		require.NoError(t, err)
		require.Empty(t, args, "%q", s)
	}
}
