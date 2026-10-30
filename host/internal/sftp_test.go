package internal

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSFTPSession_resolvePath(t *testing.T) {
	session := &SFTPSession{
		readOnly: false,
	}

	// Test cases for path resolution:
	// - Absolute paths (starting with /) are used as-is
	// - Relative paths are passed through (WithStartDirectory handles them at protocol level)
	//
	// There are deliberately no tilde cases. Tilde expansion is not part of
	// SFTP, and the branch that used to handle it could never run in
	// production: the library resolves every request against the start
	// directory first, so a handler never sees a path still starting with "~".
	// Testing resolvePath directly bypassed that and made the dead code look
	// alive.
	tests := []struct {
		name     string
		reqPath  string
		wantPath string
	}{
		// Absolute paths - used as-is
		{
			name:     "filesystem root",
			reqPath:  "/",
			wantPath: "/",
		},
		{
			name:     "absolute path",
			reqPath:  "/tmp/file.txt",
			wantPath: "/tmp/file.txt",
		},
		{
			name:     "absolute nested path",
			reqPath:  "/var/log/syslog",
			wantPath: "/var/log/syslog",
		},
		{
			name:     "absolute path with double dots",
			reqPath:  "/tmp/../etc/passwd",
			wantPath: "/etc/passwd",
		},
		// Relative paths - passed through as-is (library handles with WithStartDirectory)
		{
			name:     "relative file passed through",
			reqPath:  "file.txt",
			wantPath: "file.txt",
		},
		{
			name:     "relative directory",
			reqPath:  "Downloads",
			wantPath: "Downloads",
		},
		{
			name:     "relative nested path passed through",
			reqPath:  "Documents/file.txt",
			wantPath: "Documents/file.txt",
		},
		{
			name:     "dot passed through",
			reqPath:  ".",
			wantPath: ".",
		},
		{
			name:     "dot-slash prefix cleaned",
			reqPath:  "./Downloads",
			wantPath: "Downloads",
		},
		{
			name:     "dot-slash nested cleaned",
			reqPath:  "./Documents/file.txt",
			wantPath: "Documents/file.txt",
		},
		{
			name:     "parent directory relative",
			reqPath:  "../Downloads",
			wantPath: "../Downloads",
		},
		{
			name:     "parent then child",
			reqPath:  "../other/file.txt",
			wantPath: "../other/file.txt",
		},
		// Windows SFTP paths - leading "/" stripped for drive letter paths
		{
			name:     "windows drive path from SFTP",
			reqPath:  "/C:/Users/foo",
			wantPath: "C:/Users/foo",
		},
		{
			name:     "windows drive path lowercase",
			reqPath:  "/c:/temp/file.txt",
			wantPath: "c:/temp/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, err := session.resolvePath(tt.reqPath)
			require.NoError(t, err)
			// Use filepath.FromSlash to convert expected path to native separators
			// since filepath.Clean in resolvePath produces native paths
			assert.Equal(t, filepath.FromSlash(tt.wantPath), gotPath)
		})
	}
}

// TestUndoubleDriveLetter covers the repair itself, which is pure so that it is
// exercised on every platform rather than only on the Windows job.
func TestUndoubleDriveLetter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// What a client sending the native "C:\\Users\\me\\notes.txt" or
			// "C:/Users/me/notes.txt" produces once the server has resolved it
			// against a start directory of /C:/Users/me.
			name: "doubled drive letter is repaired",
			in:   "/C:/Users/me/C:/Users/me/notes.txt",
			want: "/C:/Users/me/notes.txt",
		},
		{
			name: "doubled across different drives",
			in:   "/C:/Users/me/D:/data/notes.txt",
			want: "/D:/data/notes.txt",
		},
		{
			name: "lowercase drive letter",
			in:   "/c:/users/me/c:/users/me/notes.txt",
			want: "/c:/users/me/notes.txt",
		},
		{
			name: "already canonical is left alone",
			in:   "/C:/Users/me/notes.txt",
			want: "/C:/Users/me/notes.txt",
		},
		{
			name: "bare drive is left alone",
			in:   "/C:",
			want: "/C:",
		},
		{
			name: "posix path without a drive letter is left alone",
			in:   "/home/me/notes.txt",
			want: "/home/me/notes.txt",
		},
		{
			name: "colon not preceded by a single letter is not a drive",
			in:   "/C:/Users/me/ab:/notes.txt",
			want: "/C:/Users/me/ab:/notes.txt",
		},
		{
			// "f:metadata" is the NTFS alternate data stream "metadata" on
			// the file "f". Reading the "/f:" as a drive would send the
			// request to drive F: instead of the file the client named.
			name: "alternate data stream on a one-letter file is not a drive",
			in:   "/C:/Users/me/f:metadata",
			want: "/C:/Users/me/f:metadata",
		},
		{
			name: "alternate data stream is not a drive even when doubled",
			in:   "/C:/Users/me/C:/Users/me/f:metadata",
			want: "/C:/Users/me/f:metadata",
		},
		{
			// A drive can end the path: this is what "ls C:" doubles into.
			name: "trailing bare drive is repaired",
			in:   "/C:/Users/me/D:",
			want: "/D:",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, undoubleDriveLetter(tt.in))
		})
	}
}

// TestSFTPSession_resolvePathWindows covers what a guest can type as the remote
// path against a Windows host. The protocol form is /C:/dir/file, but people
// reasonably type the path they see in Explorer, and the fork this replaced
// accepted those, so refusing them now would be a silent regression.
func TestSFTPSession_resolvePathWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive-letter paths only resolve on Windows")
	}

	session := &SFTPSession{}
	const want = `C:\Users\me\notes.txt`

	// These are the requests as a handler sees them, after the library has
	// resolved them against a start directory of /C:/Users/me. Only two shapes
	// reach here: `notes.txt` and `/C:/Users/me/notes.txt` both arrive already
	// canonical, and both native spellings arrive doubled, because the library
	// converts separators before it joins.
	tests := []struct {
		name    string
		reqPath string
	}{
		{
			name:    "canonical, or a relative path resolved against the start directory",
			reqPath: "/C:/Users/me/notes.txt",
		},
		{
			name:    `native C:\Users\me\notes.txt or C:/Users/me/notes.txt`,
			reqPath: "/C:/Users/me/C:/Users/me/notes.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := session.resolvePath(tt.reqPath)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestListerat(t *testing.T) {
	tempDir := t.TempDir()

	// Create some test files
	files := []string{"a.txt", "b.txt", "c.txt"}
	for _, f := range files {
		err := os.WriteFile(filepath.Join(tempDir, f), []byte("test"), 0644)
		require.NoError(t, err)
	}

	// Read directory
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	var infos []os.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		infos = append(infos, info)
	}

	lister := listerat(infos)

	// Test ListAt with offset 0
	buf := make([]os.FileInfo, 2)
	n, err := lister.ListAt(buf, 0)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)

	// Test ListAt with offset at end
	n, err = lister.ListAt(buf, int64(len(infos)))
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, 0, n)
}

type sftpConsentChecker struct {
	check func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error)
	clear func(string)
}

func (c sftpConsentChecker) CheckPermission(ctx context.Context, op consent.Operation, client consent.ClientInfo, paths ...string) (consent.Decision, error) {
	return c.check(ctx, op, client, paths...)
}
func (c sftpConsentChecker) ClearConnection(id string) {
	if c.clear != nil {
		c.clear(id)
	}
}

func TestSFTPConsent(t *testing.T) {
	t.Run("missing checker denies", func(t *testing.T) {
		s := &SFTPSession{ctx: t.Context(), logger: discardLogger()}
		path := filepath.Join(t.TempDir(), "new")
		err := (&sftpFileCmder{session: s, logger: s.logger}).Filecmd(sftp.NewRequest("Mkdir", path))
		require.Error(t, err)
		_, err = os.Stat(path)
		require.True(t, os.IsNotExist(err))
	})
	t.Run("all protected operations and complete tuples", func(t *testing.T) {
		for _, method := range []string{"Get", "Put", "Remove", "Mkdir", "Rmdir", "Rename", "Symlink", "Link", "Setstat"} {
			t.Run(method, func(t *testing.T) {
				path, target := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")
				called := false
				s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), clientInfo: consent.ClientInfo{Fingerprint: "guest", ConnectionID: "connection"}}
				s.permissionChecker = sftpConsentChecker{check: func(ctx context.Context, op consent.Operation, client consent.ClientInfo, subjects ...string) (consent.Decision, error) {
					called = true
					require.Equal(t, s.clientInfo, client)
					operations := map[string]consent.Operation{"Get": consent.OpDownload, "Put": consent.OpUpload, "Remove": consent.OpDelete, "Mkdir": consent.OpMkdir, "Rmdir": consent.OpRmdir, "Rename": consent.OpRename, "Symlink": consent.OpSymlink, "Link": consent.OpLink, "Setstat": consent.OpSetstat}
					require.Equal(t, operations[method], op)
					want := []string{path}
					if method == "Rename" || method == "Symlink" || method == "Link" {
						want = append(want, target)
					}
					require.Equal(t, want, subjects)
					return consent.Deny, errors.New("refused")
				}}
				r := sftp.NewRequest(method, path)
				r.Target = target
				var err error
				switch method {
				case "Get":
					_, err = (&sftpFileReader{session: s, logger: s.logger}).Fileread(r)
				case "Put":
					_, err = (&sftpFileWriter{session: s, logger: s.logger}).Filewrite(r)
				default:
					err = (&sftpFileCmder{session: s, logger: s.logger}).Filecmd(r)
				}
				require.Error(t, err)
				require.True(t, called)
				_, err = os.Stat(path)
				require.True(t, os.IsNotExist(err))
			})
		}
	})
	t.Run("custom checker decisions and errors", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			decision consent.Decision
			err      error
			allowed  bool
		}{
			{"allow", consent.AllowConnection, nil, true}, {"deny", consent.Deny, nil, false}, {"checker error despite allow", consent.AllowGuest, errors.New("checker unavailable"), false}, {"invalid decision", consent.Decision(255), nil, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), permissionChecker: sftpConsentChecker{check: func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
					return tc.decision, tc.err
				}}}
				path := filepath.Join(t.TempDir(), "new")
				err := (&sftpFileCmder{session: s, logger: s.logger}).Filecmd(sftp.NewRequest("Mkdir", path))
				if tc.allowed {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					_, err = os.Stat(path)
					require.True(t, os.IsNotExist(err))
				}
			})
		}
	})

	t.Run("readonly precedes checker and accept", func(t *testing.T) {
		s := &SFTPSession{ctx: t.Context(), readOnly: true, autoAccept: true, logger: discardLogger(), permissionChecker: sftpConsentChecker{check: func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			t.Fatal("hard denial prompted")
			return consent.AllowGuest, nil
		}}}
		_, err := (&sftpFileWriter{session: s, logger: s.logger}).Filewrite(sftp.NewRequest("Put", filepath.Join(t.TempDir(), "new")))
		require.Error(t, err)
		for _, method := range []string{"Remove", "Mkdir", "Rmdir", "Rename", "Symlink", "Link", "Setstat"} {
			require.Error(t, (&sftpFileCmder{session: s, logger: s.logger}).Filecmd(sftp.NewRequest(method, "unused")))
		}
	})
	t.Run("cancellation after allow prevents side effects", func(t *testing.T) {
		for _, which := range []string{"request", "channel"} {
			t.Run(which, func(t *testing.T) {
				request, cancelRequest := context.WithCancel(t.Context())
				defer cancelRequest()
				channel, cancelChannel := context.WithCancel(t.Context())
				defer cancelChannel()
				path := filepath.Join(t.TempDir(), "new")
				s := &SFTPSession{ctx: channel, logger: discardLogger(), permissionChecker: sftpConsentChecker{check: func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
					if which == "request" {
						cancelRequest()
					} else {
						cancelChannel()
					}
					return consent.AllowConnection, nil
				}}}
				r := sftp.NewRequest("Mkdir", path).WithContext(request)
				require.Error(t, (&sftpFileCmder{session: s, logger: s.logger}).Filecmd(r))
				_, err := os.Stat(path)
				require.True(t, os.IsNotExist(err))
			})
		}
	})
	t.Run("accept bypasses checker only for sftp", func(t *testing.T) {
		s := &SFTPSession{ctx: t.Context(), autoAccept: true, logger: discardLogger(), permissionChecker: sftpConsentChecker{check: func(context.Context, consent.Operation, consent.ClientInfo, ...string) (consent.Decision, error) {
			t.Fatal("accept prompted")
			return consent.Deny, nil
		}}}
		require.NoError(t, s.checkPermission(t.Context(), time.Now(), consent.OpDownload, "file"))
		require.Error(t, s.checkPermission(t.Context(), time.Now(), consent.OpExec, "command"))
	})
	t.Run("permission deadline cannot authorize late work", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), permissionChecker: sftpConsentChecker{check: func(ctx context.Context, _ consent.Operation, _ consent.ClientInfo, _ ...string) (consent.Decision, error) {
				time.Sleep(consent.PermissionTimeout)
				return consent.AllowGuest, nil
			}}}
			require.Error(t, s.checkPermission(t.Context(), time.Now(), consent.OpDownload, "file"))
		})
	})
	t.Run("transfer context outlives consent timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "file")
			require.NoError(t, os.WriteFile(path, []byte("ok"), 0600))
			s := &SFTPSession{ctx: t.Context(), autoAccept: true, logger: discardLogger()}
			reader, err := (&sftpFileReader{session: s, logger: s.logger}).Fileread(sftp.NewRequest("Get", path))
			require.NoError(t, err)
			defer reader.(io.Closer).Close()
			time.Sleep(2 * consent.PermissionTimeout)
			b := make([]byte, 2)
			_, err = reader.ReadAt(b, 0)
			require.NoError(t, err)
			require.Equal(t, "ok", string(b))
		})
	})
}

type sftpConsentPrompter func(context.Context, consent.Prompt) (consent.Decision, error)

func (f sftpConsentPrompter) Prompt(ctx context.Context, p consent.Prompt) (consent.Decision, error) {
	return f(ctx, p)
}

func TestSFTPConsentDeadline(t *testing.T) {
	t.Run("queued before manager retains handler arrival", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			prompts := make(chan consent.Prompt, 2)
			m := consent.NewManager(sftpConsentPrompter(func(ctx context.Context, p consent.Prompt) (consent.Decision, error) {
				prompts <- p
				<-ctx.Done()
				return consent.Deny, ctx.Err()
			}), discardLogger())
			defer m.Close()
			arrived := time.Now()
			s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), permissionChecker: sftpConsentChecker{check: func(ctx context.Context, op consent.Operation, c consent.ClientInfo, subjects ...string) (consent.Decision, error) {
				time.Sleep(40 * time.Second)
				return m.CheckPermission(ctx, op, c, subjects...)
			}}}
			result := make(chan error, 1)
			go func() { result <- s.checkPermission(t.Context(), arrived, consent.OpDownload, "file") }()
			synctest.Wait()
			time.Sleep(40 * time.Second)
			synctest.Wait()
			require.Equal(t, arrived.Add(consent.PermissionTimeout), (<-prompts).Deadline)
			time.Sleep(20 * time.Second)
			synctest.Wait()
			require.Error(t, <-result)
		})
	})
	t.Run("recoalesced waiter retains own deadline", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			prompts := make(chan consent.Prompt, 4)
			m := consent.NewManager(sftpConsentPrompter(func(ctx context.Context, p consent.Prompt) (consent.Decision, error) {
				prompts <- p
				<-ctx.Done()
				return consent.Deny, ctx.Err()
			}), discardLogger())
			defer m.Close()
			origin, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := &SFTPSession{ctx: t.Context(), logger: discardLogger(), permissionChecker: m, clientInfo: consent.ClientInfo{Fingerprint: "guest", ConnectionID: "one"}}
			first := make(chan error, 1)
			go func() { first <- s.checkPermission(origin, time.Now(), consent.OpDownload, "file") }()
			synctest.Wait()
			old := <-prompts
			time.Sleep(10 * time.Second)
			arrived := time.Now()
			other := *s
			other.clientInfo.ConnectionID = "two"
			second := make(chan error, 1)
			go func() { second <- other.checkPermission(t.Context(), arrived, consent.OpDownload, "file") }()
			synctest.Wait()
			time.Sleep(20 * time.Second)
			cancel()
			synctest.Wait()
			require.Error(t, <-first)
			replacement := <-prompts
			require.NotEqual(t, old.ID, replacement.ID)
			require.Equal(t, arrived.Add(consent.PermissionTimeout), replacement.Deadline)
			time.Sleep(40 * time.Second)
			synctest.Wait()
			require.Error(t, <-second)
		})
	})
}
