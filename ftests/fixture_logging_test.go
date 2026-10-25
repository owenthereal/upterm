package ftests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/pborman/ansi"
)

type emptyFixtureErrors struct{}

func (emptyFixtureErrors) Error() string   { return "empty error collection" }
func (emptyFixtureErrors) Unwrap() []error { return nil }

type fixtureDiagnostic struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	Error   string `json:"error"`
	P       []byte `json:"p"`
	PP      []byte `json:"pp"`
}

func readFixtureDiagnostic(t *testing.T, output *bytes.Buffer) fixtureDiagnostic {
	t.Helper()
	decoder := json.NewDecoder(output)
	var record fixtureDiagnostic
	if err := decoder.Decode(&record); err != nil {
		t.Fatalf("decode diagnostic: %v", err)
	}
	var extra fixtureDiagnostic
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("want exactly one diagnostic; next decode = %v, record = %+v", err, extra)
	}
	return record
}

func TestFixtureRunErrorDiagnostics(t *testing.T) {
	operationalErr := errors.New("connection failed")
	tests := []struct {
		name  string
		err   error
		level string
	}{
		{name: "success"},
		{name: "direct cancellation", err: context.Canceled, level: "DEBUG"},
		{name: "wrapped cancellation", err: fmt.Errorf("run: %w", context.Canceled), level: "DEBUG"},
		{name: "joined cancellation", err: errors.Join(context.Canceled, context.Canceled), level: "DEBUG"},
		{name: "nested cancellation", err: fmt.Errorf("run: %w", errors.Join(context.Canceled, fmt.Errorf("worker: %w", context.Canceled))), level: "DEBUG"},
		{name: "mixed join", err: errors.Join(context.Canceled, operationalErr), level: "ERROR"},
		{name: "nested mixed join", err: fmt.Errorf("run: %w", errors.Join(context.Canceled, fmt.Errorf("worker: %w", operationalErr))), level: "ERROR"},
		{name: "operational error", err: operationalErr, level: "ERROR"},
		{name: "deadline", err: context.DeadlineExceeded, level: "ERROR"},
		{name: "cancellation text", err: errors.New("context canceled"), level: "ERROR"},
		{name: "empty unwrap collection", err: emptyFixtureErrors{}, level: "ERROR"},
	}
	for _, message := range []string{"error running host", "error in client run group"} {
		t.Run(message, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					var output bytes.Buffer
					logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
					logFixtureRunError(logger, message, tt.err)
					if tt.err == nil {
						if output.Len() != 0 {
							t.Fatalf("successful run logged a diagnostic: %s", output.String())
						}
						return
					}
					record := readFixtureDiagnostic(t, &output)
					if record.Level != tt.level {
						t.Errorf("diagnostic severity = %s, want %s", record.Level, tt.level)
					}
					if record.Message != message || record.Error != tt.err.Error() {
						t.Errorf("diagnostic lost original message/error: %+v; want message %q, error %q", record, message, tt.err.Error())
					}
				})
			}
		})
	}
}

func TestFixtureANSIOutputDiagnostics(t *testing.T) {
	tests := []struct {
		name  string
		input string
		level string
		want  string
	}{
		{name: "save cursor", input: "\x1b7", level: "DEBUG"},
		{name: "restore cursor", input: "\x1b8", level: "DEBUG"},
		{name: "normal keypad", input: "\x1b>", level: "DEBUG"},
		{name: "character set zero", input: "\x1b(", level: "DEBUG"},
		{name: "character set one", input: "\x1b)", level: "DEBUG"},
		{name: "character set two", input: "\x1b*", level: "DEBUG"},
		{name: "character set three", input: "\x1b+", level: "DEBUG"},
		{name: "known collection with valid ANSI", input: "before\x1b[31mred\x1b[0m\x1b7\x1b8\x1b>\x1b(\x1b)\x1b*\x1b+after", level: "DEBUG"},
		{name: "unknown escape", input: "\x1b\t", level: "WARN"},
		{name: "mixed known unknown and valid ANSI", input: "before\x1b[31mred\x1b[0m\x1b7\x1b\tafter", level: "WARN"},
		{name: "truncated escape", input: "\x1b", level: "WARN"},
		{name: "valid ANSI", input: "before\x1b[31mred\x1b[0mafter", want: "beforeredafter"},
		{name: "plain text", input: "plain text", want: "plain text"},
		{name: "empty"},
	}
	for _, byteKey := range []string{"p", "pp"} {
		t.Run(byteKey, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					input := []byte(tt.input)
					_, parseErr := ansi.Strip(input)
					if (parseErr != nil) != (tt.level != "") {
						t.Fatalf("real parser error = %v, want error: %v", parseErr, tt.level != "")
					}
					var output bytes.Buffer
					logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
					got := stripFixtureOutput(logger, byteKey, input)
					if parseErr == nil {
						if string(got) != tt.want || output.Len() != 0 {
							t.Fatalf("successful strip = %q, diagnostics = %q; want %q without diagnostics", got, output.String(), tt.want)
						}
						return
					}
					if !bytes.Equal(got, input) {
						t.Errorf("strip error discarded original bytes: got %q, want %q", got, input)
					}
					record := readFixtureDiagnostic(t, &output)
					if record.Level != tt.level {
						t.Errorf("diagnostic severity = %s, want %s", record.Level, tt.level)
					}
					if record.Message != "failed to strip ANSI codes" || record.Error != parseErr.Error() {
						t.Errorf("diagnostic lost original message/error: %+v; want error %q", record, parseErr.Error())
					}
					payload, otherPayload := record.P, record.PP
					if byteKey == "pp" {
						payload, otherPayload = record.PP, record.P
					}
					if !bytes.Equal(payload, input) || otherPayload != nil {
						t.Errorf("diagnostic lost original %s bytes: got %q (other key %q), want %q", byteKey, payload, otherPayload, input)
					}
				})
			}
		})
	}
}
