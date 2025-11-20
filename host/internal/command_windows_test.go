//go:build windows
// +build windows

package internal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/olebedev/emitter"
	uio "github.com/owenthereal/upterm/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommand_Windows_BasicExecution verifies that commands can be started
// and executed correctly on Windows with ConPTY.
func TestCommand_Windows_BasicExecution(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

	// Use a simple command
	cmd := newCommand(
		"cmd",
		[]string{"/c", "echo", "test"},
		nil,
		os.Stdin,
		stdoutw,
		ee,
		writers,
		false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ptmx, err := cmd.Start(ctx)
	require.NoError(err, "failed to start command")

	// Run the command
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Wait for completion
	select {
	case err := <-errCh:
		assert.NoError(err, "command should complete successfully")
	case <-time.After(2 * time.Second):
		_ = ptmx.Close()
		assert.Fail("command did not complete within timeout")
	}
}

// TestCommand_Windows_JobObject verifies that on Windows,
// a job object is created and assigned to the process.
func TestCommand_Windows_JobObject(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

	// Use a long-running command that won't exit on its own
	cmd := newCommand(
		"ping",
		[]string{"-n", "100", "127.0.0.1"},
		nil,
		os.Stdin,
		stdoutw,
		ee,
		writers,
		false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ptmx, err := cmd.Start(ctx)
	require.NoError(err, "failed to start command")

	// The pty struct should have a job handle (non-zero)
	// We can't directly access private fields, but we can verify
	// that the command was started and cleanup works
	assert.NotNil(ptmx, "PTY should be created")

	// Run the command in background
	errCh := make(chan error, 1)
	runningCh := make(chan bool, 1)
	go func() {
		runningCh <- true // Signal that Run() has started
		errCh <- cmd.Run()
	}()

	// Wait for cmd.Run() to start
	<-runningCh

	// Give the command time to actually start executing
	time.Sleep(200 * time.Millisecond)

	// Verify command is still running (hasn't terminated yet)
	select {
	case <-errCh:
		assert.Fail("command should still be running before Close()")
	default:
		// Good - command is still running
	}

	// Close the PTY - this should:
	// 1. Close the job object handle
	// 2. OS sees JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag
	// 3. OS terminates all processes in the job
	err = ptmx.Close()
	assert.NoError(err, "PTY close should succeed")

	// Command should terminate shortly after PTY close
	// ONLY the job object can cause this - we didn't cancel context,
	// we didn't send any signals, we just closed the PTY.
	// The process termination proves job object cleanup worked.
	select {
	case err := <-errCh:
		// Command terminated - this is what we expect
		// The error might be non-nil (terminated by OS), which is fine
		if err != nil {
			t.Logf("command terminated with error (expected from job kill): %v", err)
		}
		// Success - job object cleanup worked
	case <-time.After(2 * time.Second):
		// If we reach here, the command is still running after Close()
		// This means job object cleanup FAILED
		assert.Fail("command did not terminate after job object close - job object cleanup may have failed")
	}
}

// TestCommand_Windows_ConPTY verifies Windows-specific ConPTY functionality.
// This test validates that ConPTY can be created and used to run commands,
// and that command output is properly captured through the ConPTY.
func TestCommand_Windows_ConPTY(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Create a pipe to capture stdout
	stdoutr, stdoutw, err := os.Pipe()
	require.NoError(err, "failed to create stdout pipe")
	defer func() { _ = stdoutr.Close() }()
	defer func() { _ = stdoutw.Close() }()

	ee := &emitter.Emitter{}
	writers := uio.NewMultiWriter(5)

	// Run a simple command through ConPTY
	// Use 'cmd /c echo' which is simple and reliable on Windows
	cmd := newCommand(
		"cmd",
		[]string{"/c", "echo", "ConPTY test successful"},
		nil,
		os.Stdin, // Pass stdin so startPty can attempt to get size
		stdoutw,
		ee,
		writers,
		false,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Start the command - this will create the ConPTY
	_, err = cmd.Start(ctx)
	require.NoError(err, "failed to start command with ConPTY")

	// Capture output in background
	outputCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 1024)
		var output []byte
		for {
			n, err := stdoutr.Read(buf)
			if n > 0 {
				output = append(output, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		// Only send if we captured output (don't send empty string)
		if len(output) > 0 {
			outputCh <- string(output)
		}
	}()

	// Run the command
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Run()
	}()

	// Wait for command to complete
	select {
	case err := <-errCh:
		// Command should complete successfully
		assert.NoError(err, "command should complete successfully")

		// Verify we got output through ConPTY
		_ = stdoutw.Close()
		output := <-outputCh
		assert.Contains(output, "ConPTY test successful", "should see command output through ConPTY")
		t.Logf("ConPTY output: %q", output)
	case <-time.After(2500 * time.Millisecond):
		cancel()
		<-errCh // Wait for goroutine to finish
		assert.Fail("command did not complete within timeout")
	}
}
