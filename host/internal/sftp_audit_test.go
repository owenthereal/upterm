package internal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func sftpAuditRecords(t *testing.T, output *recordingWriter) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(output.bytes())), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "SFTP permission policy" {
			records = append(records, record)
		}
	}
	return records
}

func requireSFTPAudit(t *testing.T, record map[string]any, op, outcome string, subjects []string) string {
	t.Helper()
	require.Equal(t, "sftp", record["capability"])
	require.Equal(t, op, record["operation"])
	require.Equal(t, outcome, record["outcome"])
	require.Contains(t, record, "fingerprint")
	require.Contains(t, record, "connection_id")
	id, ok := record["request_id"].(string)
	require.True(t, ok)
	require.NotEmpty(t, id)
	for _, r := range id {
		require.True(t, r >= 0x20 && r <= 0x7e)
	}
	require.Less(t, len(id), 128)
	projected := make([]any, 0, len(subjects))
	for _, subject := range subjects {
		if len(subject) > 256 {
			subject = subject[:256] + "..."
		}
		projected = append(projected, strconv.QuoteToASCII(subject))
	}
	require.Equal(t, projected, record["subjects"])
	return id
}

func TestSFTPAudit(t *testing.T) {
	for _, tc := range []struct {
		name, outcome    string
		accept, readonly bool
		decision         consent.Decision
		err              error
		nilChecker       bool
	}{
		{name: "pregrant", outcome: "allowed", accept: true},
		{name: "readonly preempts pregrant", outcome: "denied", accept: true, readonly: true},
		{name: "nil checker", outcome: "unavailable", nilChecker: true},
		{name: "custom allow", outcome: "allowed", decision: consent.AllowConnection},
		{name: "custom denial", outcome: "denied"},
		{name: "unavailable", outcome: "unavailable", err: consent.ErrUnavailable},
		{name: "timeout", outcome: "timeout", err: consent.ErrTimeout},
		{name: "deadline", outcome: "timeout", err: context.DeadlineExceeded},
		{name: "cancelled", outcome: "canceled", err: consent.ErrCanceled},
		{name: "context cancelled", outcome: "canceled", err: context.Canceled},
		{name: "overloaded", outcome: "overloaded", err: consent.ErrOverloaded},
		{name: "late answer", outcome: "stale", err: consent.ErrStale},
		{name: "oversize", outcome: "subject_too_large", err: consent.ErrSubjectTooLarge},
		{name: "checker error", outcome: "denied", err: errors.New("custom failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &recordingWriter{}
			logger := slog.New(slog.NewJSONHandler(output, nil))
			s := &SFTPSession{ctx: t.Context(), logger: logger, autoAccept: tc.accept, readOnly: tc.readonly, clientInfo: consent.ClientInfo{Fingerprint: "guest", ConnectionID: "connection"}}
			if !tc.nilChecker {
				s.permissionChecker = sftpConsentChecker{check: func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
					require.False(t, tc.accept || tc.readonly, "bypass reached custom checker")
					return tc.decision, tc.err
				}}
			}
			path := filepath.Join(t.TempDir(), "new")
			err := (&sftpFileCmder{session: s, logger: logger}).Filecmd(sftp.NewRequest("Mkdir", path))
			if tc.outcome == "allowed" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				_, err = os.Stat(path)
				require.True(t, os.IsNotExist(err))
			}
			records := sftpAuditRecords(t, output)
			require.Len(t, records, 1)
			requireSFTPAudit(t, records[0], "mkdir", tc.outcome, []string{path})
			require.Equal(t, strconv.QuoteToASCII("guest"), records[0]["fingerprint"])
			require.Equal(t, strconv.QuoteToASCII("connection"), records[0]["connection_id"])
		})
	}
	t.Run("cached grant has a new boundary identity", func(t *testing.T) {
		output := &recordingWriter{}
		logger := slog.New(slog.NewJSONHandler(output, nil))
		prompts := 0
		manager := consent.NewManager(sftpConsentPrompter(func(context.Context, consent.Prompt) (consent.Decision, error) {
			prompts++
			return consent.AllowConnection, nil
		}), logger)
		defer manager.Close()
		s := &SFTPSession{ctx: t.Context(), logger: logger, permissionChecker: manager, clientInfo: consent.ClientInfo{Fingerprint: "guest", ConnectionID: "connection"}}
		path := filepath.Join(t.TempDir(), "new")
		handler := &sftpFileCmder{session: s, logger: logger}
		require.NoError(t, handler.Filecmd(sftp.NewRequest("Mkdir", path)))
		require.NoError(t, handler.Filecmd(sftp.NewRequest("Setstat", path)))
		records := sftpAuditRecords(t, output)
		require.Len(t, records, 2)
		first := requireSFTPAudit(t, records[0], "mkdir", "allowed", []string{path})
		second := requireSFTPAudit(t, records[1], "setstat", "allowed", []string{path})
		require.NotEqual(t, first, second)
		require.Equal(t, 1, prompts)
		for _, line := range strings.Split(strings.TrimSpace(string(output.bytes())), "\n") {
			var record map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			if record["msg"] == "consent decision" {
				require.NotEqual(t, first, record["request_id"])
				require.NotEqual(t, second, record["request_id"])
			}
		}
	})
	t.Run("readonly paired paths and upload are audited", func(t *testing.T) {
		output := &recordingWriter{}
		logger := slog.New(slog.NewJSONHandler(output, nil))
		s := &SFTPSession{ctx: t.Context(), logger: logger, readOnly: true, autoAccept: true}
		path, target := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")
		request := sftp.NewRequest("Rename", path)
		request.Target = target
		require.Error(t, (&sftpFileCmder{session: s, logger: logger}).Filecmd(request))
		_, err := (&sftpFileWriter{session: s, logger: logger}).Filewrite(sftp.NewRequest("Put", path))
		require.Error(t, err)
		records := sftpAuditRecords(t, output)
		require.Len(t, records, 2)
		first := requireSFTPAudit(t, records[0], "rename", "denied", []string{path, target})
		second := requireSFTPAudit(t, records[1], "upload", "denied", []string{path})
		require.NotEqual(t, first, second)
	})
	t.Run("untrusted projections stay bounded without changing policy subjects", func(t *testing.T) {
		output := &recordingWriter{}
		logger := slog.New(slog.NewJSONHandler(output, nil))
		source := "/source\x1b[2J\n\u202e" + strings.Repeat("x", 4000)
		target := "/target\r\x00" + strings.Repeat("z", 4000)
		fingerprint, connection := "guest\x1b\n"+strings.Repeat("g", 4000), "connection\r\u202e"+strings.Repeat("c", 4000)
		s := &SFTPSession{ctx: t.Context(), logger: logger, clientInfo: consent.ClientInfo{Fingerprint: fingerprint, ConnectionID: connection}, permissionChecker: sftpConsentChecker{check: func(_ context.Context, _ consent.Operation, client consent.ClientInfo, paths ...string) (consent.Decision, error) {
			require.Equal(t, []string{source, target}, paths)
			require.Equal(t, fingerprint, client.Fingerprint)
			require.Equal(t, connection, client.ConnectionID)
			return consent.Deny, errors.New("reason\x1b\n" + strings.Repeat("e", 4000))
		}}}
		request := sftp.NewRequest("Rename", source)
		request.Target = target
		require.Error(t, (&sftpFileCmder{session: s, logger: logger}).Filecmd(request))
		records := sftpAuditRecords(t, output)
		require.Len(t, records, 1)
		requireSFTPAudit(t, records[0], "rename", "denied", []string{source, target})
		for _, key := range []string{"fingerprint", "connection_id", "reason"} {
			value := records[0][key].(string)
			require.Less(t, len(value), 1600)
			for _, r := range value {
				require.True(t, r >= 0x20 && r <= 0x7e)
			}
		}
	})
	t.Run("logging cannot bypass final cancellation check", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		output := &recordingWriter{}
		logger := slog.New(sftpAuditCancelHandler{slog.NewJSONHandler(output, nil), cancel})
		s := &SFTPSession{ctx: ctx, logger: logger, autoAccept: true}
		path := filepath.Join(t.TempDir(), "new")
		require.Error(t, (&sftpFileCmder{session: s, logger: logger}).Filecmd(sftp.NewRequest("Mkdir", path)))
		_, err := os.Stat(path)
		require.True(t, os.IsNotExist(err))
		records := sftpAuditRecords(t, output)
		require.Len(t, records, 1)
		requireSFTPAudit(t, records[0], "mkdir", "allowed", []string{path})
	})
}

type sftpAuditCancelHandler struct {
	slog.Handler
	cancel context.CancelFunc
}

func (h sftpAuditCancelHandler) Handle(ctx context.Context, r slog.Record) error {
	err := h.Handler.Handle(ctx, r)
	if r.Message == "SFTP permission policy" {
		h.cancel()
	}
	return err
}
func (h sftpAuditCancelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return sftpAuditCancelHandler{h.Handler.WithAttrs(attrs), h.cancel}
}
func (h sftpAuditCancelHandler) WithGroup(name string) slog.Handler {
	return sftpAuditCancelHandler{h.Handler.WithGroup(name), h.cancel}
}
