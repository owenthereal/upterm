package command

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A program that says it is running and then waits for its stdin to close.
const waitingProgram = `package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	fmt.Println("running")
	_, _ = io.Copy(io.Discard, os.Stdin)
}
`

// buildWaitingProgram compiles waitingProgram to exe.
func buildWaitingProgram(t *testing.T, exe string) {
	t.Helper()

	goTool, err := exec.LookPath("go")
	require.NoError(t, err)

	src := filepath.Join(t.TempDir(), "main.go")
	require.NoError(t, os.WriteFile(src, []byte(waitingProgram), 0o644))

	cmd := exec.Command(goTool, "build", "-o", exe, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// Windows lets a running .exe be renamed but not overwritten or deleted, so
// replacing one is the rename in installBinary, and the file set aside can be
// removed once the program has stopped.
func TestInstallReplacesABinaryWhileItRuns(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "upterm.exe")
	buildWaitingProgram(t, exe)

	cmd := exec.Command(exe)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	started := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		started <- line
	}()
	select {
	case line := <-started:
		require.Equal(t, "running", strings.TrimSpace(line))
	case <-time.After(30 * time.Second):
		t.Fatal("the program didn't start")
	}

	// What makes replacing it more than a write.
	require.Error(t, os.WriteFile(exe, []byte("x"), 0o755), "a running binary can be overwritten")

	require.NoError(t, installBinary(tarball(t, "upterm.exe", "new"), exe, "windows"))

	got, err := os.ReadFile(exe)
	require.NoError(t, err)
	require.Equal(t, "new", string(got))
	_, aside := splitSetAside(t, filepath.Dir(exe), "upterm.exe")
	require.Len(t, aside, 1, "the running binary is set aside")

	// The program carries on to a clean exit.
	require.NoError(t, stdin.Close())
	require.NoError(t, cmd.Wait())

	// A backup of the user's, by the plain name, is not upterm's to clear.
	require.NoError(t, os.WriteFile(exe+".old", []byte("a backup"), 0o644))

	removeStaleOld(exe, "windows")
	rest, aside := splitSetAside(t, filepath.Dir(exe), "upterm.exe")
	require.Empty(t, aside, "the next upgrade clears it")
	require.ElementsMatch(t, []string{"upterm.exe", "upterm.exe.old"}, rest)
}
