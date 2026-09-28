//go:build windows

package sessiondir

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, which x/sys/windows does not export:
// STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | the file-specific rights. It is
// what GENERIC_ALL maps to on a file or a directory.
const fileAllAccess = 0x1F01FF

// x/sys/windows exports neither the mandatory-label ACE type nor the
// mandatory policy bits that make up such an ACE's mask.
const (
	systemMandatoryLabelACEType = 0x11
	noWriteUp                   = 0x1
	noReadUp                    = 0x2
	noExecuteUp                 = 0x4
)

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

// The DACL above names the account SID, and UAC's split tokens share it: with
// no mandatory label, a medium-integrity process of the same user passes that
// DACL and can open attach.sock in an elevated session's directory, which is
// command input to an elevated pty. Claim therefore also labels the directory
// at the level its own token holds — a process may set no label above its
// own — so the unelevated half of a split token is denied by the mandatory
// policy before the DACL is ever consulted.
//
// Like the DACL test above, this walks the ACE instead of matching the SDDL
// text: the label is a mask and two inheritance flags, and the order Windows
// chooses to print their mnemonics in ("NRNWNX" against "NWNRNX") is its own.
// A test that pinned the text would fail for a reason that has nothing to do
// with who can open the socket. The SDDL is printed in every failure message
// instead, as the readable form of whatever went wrong.
//
// What this cannot show, on CI or anywhere else at a single integrity level:
// that a lower-integrity process is actually refused when it connects. This
// asserts the label is on the directory, inheritable, at this process's own
// level — the precondition for that refusal, not the refusal.
func Test_Claim_LabelsTheRuntimeDirectoryAtItsOwnIntegrityLevelOnWindows(t *testing.T) {
	root, err := os.MkdirTemp("", "up")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	d, err := Claim(context.Background(), ClaimOptions{RuntimeRoot: root, StateRoot: root, Name: "labelled"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = d.Release(context.Background()) })

	want := currentProcessIntegritySID(t)

	sd, err := windows.GetNamedSecurityInfo(d.runtime, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION)
	require.NoError(t, err)
	sacl, _, err := sd.SACL()
	require.NoError(t, err,
		"no mandatory label on the directory, so a medium-integrity process of this user may open the sockets in it: %s", sd)
	require.NotNil(t, sacl, "an empty SACL is no label at all: %s", sd)
	require.NotZero(t, sacl.AceCount, "an empty SACL is no label at all: %s", sd)

	var labelled, onTheDirectory bool
	for i := uint32(0); i < uint32(sacl.AceCount); i++ {
		// A label ACE has the same header/mask/SID layout; only its type
		// differs, and x/sys/windows types GetAce's out-parameter this way.
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(sacl, i, &ace))
		if ace.Header.AceType != systemMandatoryLabelACEType {
			continue
		}

		// Compared as strings, not through SubAuthority: that accessor
		// returns a pointer into this Go-allocated descriptor and faults
		// under -race, which is what the first Windows CI run found. The
		// string is the whole SID, so this asserts the level and the
		// authority it belongs to at once.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		require.Equal(t, want, sid,
			"labelled %s, not at this process's own level %s: a label above this process's level would have been refused, one below it lets a lower-integrity process in: %s", sid, want, sd)

		require.Equal(t, windows.ACCESS_MASK(noReadUp|noWriteUp|noExecuteUp), ace.Mask,
			"the mandatory policy is %#x, not deny read-up, write-up and execute-up: %s", ace.Mask, sd)
		const bothKinds = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		require.Equal(t, uint8(bothKinds), ace.Header.AceFlags&bothKinds,
			"the sockets bound inside inherit no label: %s", sd)

		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
			onTheDirectory = true
		}
		labelled = true
	}
	require.True(t, labelled,
		"the SACL holds no mandatory label ACE, so nothing here separates this process from the other half of a split token: %s", sd)
	require.True(t, onTheDirectory, "every label ACE is inherit-only, so the directory itself carries no level: %s", sd)
}

// A token whose integrity level cannot be read fails the whole directory
// setup, and Claim removes the directory when securing fails, so the session
// never starts. The alternative — labelling with a guess, or carrying on
// unlabelled — is the elevated hole this closes, and it would be silent.
func Test_tokenIntegrityRID_RefusesAnUnreadableToken(t *testing.T) {
	rid, err := tokenIntegrityRID(windows.Token(windows.InvalidHandle))
	require.Error(t, err, "an unreadable token must not yield a level to label a directory with")
	require.Zero(t, rid, "a level was returned alongside the error, and a caller could label with it")
}

// The level a directory is labelled with is only ever as good as the parse
// that produced it, so anything that is not a mandatory label SID has to come
// back as "no level" rather than as a number. Windows writes these with
// ConvertSidToStringSid, which is why the match is exact and case-sensitive:
// a string in any other shape did not come from where it should have.
func Test_integrityRIDFromSID(t *testing.T) {
	for _, c := range []struct {
		sid  string
		rid  uint32
		want bool
	}{
		{sid: "S-1-16-4096", rid: 0x1000, want: true},
		{sid: "S-1-16-8192", rid: 0x2000, want: true},
		{sid: "S-1-16-12288", rid: 0x3000, want: true},
		{sid: "S-1-16-16384", rid: 0x4000, want: true},
		{sid: "S-1-5-21-1004336348-1177238915-682003330-512"}, // a group, not a level
		{sid: "S-1-16-12288-1"},                               // an integrity SID has one sub-authority
		{sid: "S-1-16-"},                                      // truncated
		{sid: "S-1-16-4294967296"},                            // past the field
		{sid: "S-1-16-0x3000"},                                // not how Windows writes it
		{sid: "s-1-16-12288"},                                 // nor this
		{sid: ""},                                             // what String() returns when it fails
	} {
		t.Run(c.sid, func(t *testing.T) {
			rid, ok := integrityRIDFromSID(c.sid)
			require.Equal(t, c.want, ok)
			require.Equal(t, c.rid, rid, "a level was returned for a SID that carries none")
		})
	}
}

// currentProcessIntegritySID reads this process's own integrity SID through
// the pseudo token, which is a different handle and a different retry shape
// from what secureSessionDir uses, and returns the whole SID rather than a
// parsed level so that nothing the code under test does is reused here. The
// expectation the label is measured against must not come from the code that
// wrote the label.
func currentProcessIntegritySID(t *testing.T) string {
	t.Helper()

	token := windows.GetCurrentProcessToken() // a pseudo handle; nothing to close

	// []uint64 rather than []byte, for the alignment the cast below needs: it
	// converts to a type holding a *SID, and checkptr fatals on a conversion
	// to a pointer-bearing type at an address that is not aligned to it. A
	// constant-size []byte that does not escape is a stack array of alignment
	// one, and this is the line that killed the first Windows CI run to reach
	// it. Do not simplify it back.
	buf := make([]uint64, 8)
	var n uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &n)
	if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		buf = make([]uint64, (int(n)+7)/8)
		err = windows.GetTokenInformation(token, windows.TokenIntegrityLevel,
			(*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &n)
	}
	require.NoError(t, err, "reading this process's integrity level")

	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	require.NotNil(t, sid, "this process's token carries no integrity SID")
	text := sid.String()
	require.True(t, strings.HasPrefix(text, "S-1-16-"),
		"%q is not an integrity SID, so it is not a level this test can hold the label to", text)
	return text
}
