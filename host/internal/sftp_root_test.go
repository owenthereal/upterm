package internal

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/owenthereal/upterm/host/consent"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/require"
)

func TestRootedSFTPRetainsConsentAndReadOnly(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	require.NoError(t, root.WriteFile("file", []byte("inside"), 0600))
	for _, policy := range []string{"no checker", "denied", "readonly", "auto", "allowed"} {
		t.Run(policy, func(t *testing.T) {
			s := &SFTPSession{root: root, ctx: t.Context(), logger: discardLogger()}
			called := false
			switch policy {
			case "readonly":
				s.readOnly, s.autoAccept = true, true
			case "auto":
				s.autoAccept = true
			}
			if policy != "no checker" {
				s.permissionChecker = sftpConsentChecker{check: func(_ context.Context, _ consent.Operation, _ consent.ClientInfo, paths ...string) (consent.Decision, error) {
					called = true
					require.Equal(t, []string{"file"}, paths)
					if policy == "allowed" {
						return consent.AllowConnection, nil
					}
					return consent.Deny, nil
				}}
			}
			reader, err := (&sftpFileReader{session: s, logger: s.logger}).Fileread(sftp.NewRequest("Get", filepath.Join(root.Name(), "file")))
			if policy == "no checker" || policy == "denied" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				data := make([]byte, 6)
				_, err = reader.ReadAt(data, 0)
				require.NoError(t, err)
				require.Equal(t, "inside", string(data))
				require.NoError(t, reader.(io.Closer).Close())
			}
			if policy == "readonly" {
				_, err = (&sftpFileWriter{session: s, logger: s.logger}).Filewrite(sftp.NewRequest("Put", "file"))
				require.Error(t, err)
				require.Error(t, (&sftpFileCmder{session: s, logger: s.logger}).Filecmd(sftp.NewRequest("Remove", "file")))
			}
			require.Equal(t, policy == "denied" || policy == "allowed", called)
		})
	}
	closedRoot, err := os.OpenRoot(root.Name())
	require.NoError(t, err)
	require.NoError(t, closedRoot.Close())
	s := &SFTPSession{root: closedRoot, ctx: t.Context(), autoAccept: true, logger: discardLogger()}
	_, err = (&sftpFileReader{session: s, logger: s.logger}).Fileread(sftp.NewRequest("Get", filepath.Join(root.Name(), "file")))
	require.Error(t, err, "a closed root must never fall back to ambient access")
}

func TestRootedSFTPRejectsForeignVolumesAndDevices(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer func() { require.NoError(t, root.Close()) }()
	for _, name := range []string{"..", "../escape", "/outside", "C:/outside", "C:relative", "//server/share/file", `\\?\C:\file`, "file:stream", "NUL", "NUL.txt", "COM1", "COM¹", "LPT9", "CONOUT$", "dir/PRN", "bad\x00name"} {
		t.Run(name, func(t *testing.T) {
			_, err := rootedSFTPPath(root, name)
			require.Error(t, err)
		})
	}
}
