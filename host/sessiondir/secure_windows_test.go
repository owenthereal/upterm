//go:build windows

package sessiondir

import (
	"context"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, which x/sys/windows does not export:
// STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | the file-specific rights. It is
// what GENERIC_ALL maps to on a file or a directory.
const fileAllAccess = 0x1F01FF

// The session's runtime directory holds the attach socket, which grants
// command input to whoever can open it. os.Mkdir(…, 0700) sets nothing on
// Windows: the directory inherits whatever its parent grants. Claim has to
// replace that with a DACL of its own — protected, so nothing is inherited,
// and naming the current user alone — before a socket is bound in it.
//
// The assertions walk the ACEs rather than matching the SDDL text, because
// the text is Windows' to choose and it makes two substitutions here. It
// splits one inheritable GENERIC_ALL ACE into a pair — an effective one
// carrying the mapped specific rights and an inherit-only one keeping the
// generic rights — so the count is not ours to predict; and it abbreviates
// well-known SIDs, so a runner whose account is the built-in administrator
// prints "LA" where the user's own SID string was expected. Neither changes
// who may open the socket, which is what this test is about: every ACE is an
// allow ACE, for this user, granting full control, with the directory itself
// covered and its children inheriting.
func Test_Claim_SecuresTheRuntimeDirectoryOnWindows(t *testing.T) {
	root, err := os.MkdirTemp("", "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	d, err := Claim(context.Background(), ClaimOptions{RuntimeRoot: root, StateRoot: root, Name: "secured"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Release(context.Background()) })

	sd, err := windows.GetNamedSecurityInfo(d.runtime, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	require.NoError(t, err)
	control, _, err := sd.Control()
	require.NoError(t, err)
	require.NotZero(t, control&windows.SE_DACL_PROTECTED, "inheritance must be cut off, or the parent's grants apply: %s", sd)

	token, err := windows.OpenCurrentProcessToken()
	require.NoError(t, err)
	defer token.Close()
	user, err := token.GetTokenUser()
	require.NoError(t, err)

	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, dacl, "a nil DACL grants everyone everything: %s", sd)
	require.NotZero(t, dacl.AceCount, "an empty DACL denies even this user: %s", sd)

	var onTheDirectory, inheritedByChildren bool
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(dacl, i, &ace))

		require.Equal(t, uint8(windows.ACCESS_ALLOWED_ACE_TYPE), ace.Header.AceType,
			"ACE %d is not an allow ACE: %s", i, sd)
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		require.True(t, sid.Equals(user.User.Sid),
			"ACE %d names %s, not this user %s: %s", i, sid, user.User.Sid, sd)
		require.Contains(t, []windows.ACCESS_MASK{windows.GENERIC_ALL, fileAllAccess}, ace.Mask,
			"ACE %d grants %#x, which is neither GENERIC_ALL nor FILE_ALL_ACCESS: %s", i, ace.Mask, sd)

		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			onTheDirectory = true
		}
		const bothKinds = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		if ace.Header.AceFlags&bothKinds == bothKinds {
			inheritedByChildren = true
		}
	}
	require.True(t, onTheDirectory, "no ACE applies to the directory itself: %s", sd)
	require.True(t, inheritedByChildren, "the sockets bound inside inherit nothing: %s", sd)
}
