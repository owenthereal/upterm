package capacity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

// Fault behavior belongs to the test executable, never the deployed helper.
// Each copy gets a sidecar so Host can invoke its normal helper arguments on
// every platform without a shell, inherited environment, or production mode.
type faultHelperConfig struct {
	Mode   string
	Replay string
}

func faultHelperExecutable(t *testing.T, mode, replay string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	name := "fault-helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy fault helper: copy=%v close=%v", copyErr, closeErr)
	}
	config, err := json.Marshal(faultHelperConfig{Mode: mode, Replay: replay})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".json", config, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func faultHelper(t *testing.T, mode, replay string) Config {
	t.Helper()
	c := localRelay(t)
	c.HelperExecutable = faultHelperExecutable(t, mode, replay)
	return c
}

func runFaultHelper(config faultHelperConfig, in *os.File, out io.Writer) error {
	if term.IsTerminal(int(in.Fd())) {
		state, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer func() { _ = term.Restore(int(in.Fd()), state) }()
	}
	if config.Mode == "geometry" {
		return runGeometryHelper(config.Replay, in, out)
	}
	if _, err := io.WriteString(out, config.Replay); err != nil {
		return err
	}
	inputs, challenges := 0, 0
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CAP ") || len(line) != 127 {
			continue
		}
		b := []byte(line + "\n")
		switch b[4] {
		case 'R':
			challenges++
			if config.Mode == "retry" && challenges == 1 {
				continue
			}
			b[4] = 'A'
		case 'Q':
			b[4] = 'B'
		case 'F':
			if config.Mode == "silent" {
				continue
			}
			if config.Mode != "replay" {
				b[4] = 'B'
			}
			if config.Mode == "missing-host-suffix" {
				copy(b[15:23], "00000001")
			}
		case 'I':
			inputs++
			switch config.Mode {
			case "silent":
				if inputs > 1 {
					continue
				}
			case "late":
				if inputs == 2 {
					time.Sleep(1200 * time.Millisecond)
				}
				if inputs > 2 {
					continue
				}
			case "corrupt":
				if inputs > 1 {
					b[126] = 'y'
				}
			}
		default:
			if config.Mode != "missing-host-suffix" && config.Mode != "replay" {
				continue
			}
		}
		if _, err := out.Write(b); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func runFaultHelperProcess() int {
	configPath, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	data, err := os.ReadFile(configPath + ".json")
	var config faultHelperConfig
	if err == nil {
		err = json.Unmarshal(data, &config)
	}
	if err == nil {
		err = runFaultHelper(config, os.Stdin, os.Stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
