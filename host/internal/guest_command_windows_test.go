//go:build windows

package internal

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Only a native Windows run executes this test; cross-compilation proves only
// that it and the implementation build there.
func TestGuestCommandWindowsInterpreter(t *testing.T) {
	argv, err := guestExecArgv("")
	require.NoError(t, err)
	raw := `Write-Output 'a b|$value"quoted'; Write-Output data | ForEach-Object { $_ }; exit 7`
	want := "a b|$value\"quoted\r\ndata\r\n"
	if strings.HasSuffix(strings.ToLower(argv[0]), "cmd.exe") {
		raw = `echo a b $value "quoted" ^| literal & echo data|findstr data & exit /b 7`
		want = "a b $value \"quoted\" | literal \r\ndata\r\n"
	}
	argv, err = guestExecArgv(raw)
	require.NoError(t, err)
	require.Equal(t, raw, argv[len(argv)-1])
	cmd := exec.Command(argv[0], argv[1:]...)
	prepareGuestCommand(cmd)
	out, err := cmd.CombinedOutput()
	var status *exec.ExitError
	require.ErrorAs(t, err, &status)
	require.Equal(t, 7, status.ExitCode())
	require.Equal(t, want, string(out))
}

func TestGuestCommandWindowsCmdSerialization(t *testing.T) {
	path, err := exec.LookPath("cmd.exe")
	require.NoError(t, err)
	raw := `echo "a b" ^| $value & exit /b 9`
	cmd := exec.Command(path, "/D", "/S", "/C", raw)
	prepareGuestCommand(cmd)
	require.NotNil(t, cmd.SysProcAttr)
	require.Contains(t, cmd.SysProcAttr.CmdLine, ` /D /S /C "`+raw+`"`)
	out, err := cmd.CombinedOutput()
	var status *exec.ExitError
	require.ErrorAs(t, err, &status)
	require.Equal(t, 9, status.ExitCode())
	require.Contains(t, string(out), `"a b" | $value`)
}
