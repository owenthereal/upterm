package command

import (
	"testing"

	"github.com/owenthereal/upterm/host/sftp"
	"github.com/stretchr/testify/require"
)

func TestTransferPromptSaysGuest(t *testing.T) {
	const id = "SHA256:abc"
	for _, tc := range []struct {
		name     string
		op       sftp.Operation
		path, to string
		want     string
	}{
		{"download", sftp.OpDownload, "~/a", "", "Guest [SHA256:abc] wants to download:\n~/a"},
		{"upload", sftp.OpUpload, "~/a", "", "Guest [SHA256:abc] wants to upload:\n~/a"},
		{"delete", sftp.OpDelete, "~/a", "", "Guest [SHA256:abc] wants to delete:\n~/a"},
		{"rmdir", sftp.OpRmdir, "~/a", "", "Guest [SHA256:abc] wants to delete:\n~/a"},
		{"mkdir", sftp.OpMkdir, "~/a", "", "Guest [SHA256:abc] wants to create directory:\n~/a"},
		{"rename", sftp.OpRename, "~/a", "~/b", "Guest [SHA256:abc] wants to rename:\n~/a → ~/b"},
		{"rename without a target", sftp.OpRename, "~/a", "", "Guest [SHA256:abc] wants to rename:\n~/a"},
		{"symlink", sftp.OpSymlink, "~/a", "~/b", "Guest [SHA256:abc] wants to create symlink:\n~/a → ~/b"},
		{"symlink without a target", sftp.OpSymlink, "~/a", "", "Guest [SHA256:abc] wants to create symlink:\n~/a"},
		{"link", sftp.OpLink, "~/a", "~/b", "Guest [SHA256:abc] wants to create hard link:\n~/a → ~/b"},
		{"link without a target", sftp.OpLink, "~/a", "", "Guest [SHA256:abc] wants to create hard link:\n~/a"},
		{"setstat", sftp.OpSetstat, "~/a", "", "Guest [SHA256:abc] wants to modify file attributes:\n~/a"},
		{"an operation with no wording of its own", sftp.Operation(99), "~/a", "", "Guest [SHA256:abc] wants to unknown:\n~/a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, transferPrompt(tc.op, id, tc.path, tc.to))
		})
	}
}
