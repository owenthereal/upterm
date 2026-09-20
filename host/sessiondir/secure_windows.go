//go:build windows

package sessiondir

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// secureSessionDir gives the directory a DACL of its own: protected, so it
// inherits nothing from its parent, and granting full control to the current
// user and nobody else; then a mandatory label at this process's own
// integrity level. Objects created inside — the sockets — inherit both.
//
// os.Mkdir's mode means nothing on Windows; a directory under a shared or
// unusual XDG_RUNTIME_DIR would otherwise grant whatever its parent grants,
// and the attach socket inside it grants command input to whoever can open
// it. Microsoft documents that AF_UNIX sockets enforce filesystem
// permissions on connect; this is the permission they enforce.
func secureSessionDir(path string) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("sessiondir: open process token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("sessiondir: current user: %w", err)
	}

	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("sessiondir: build DACL: %w", err)
	}

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("sessiondir: set DACL on %s: %w", path, err)
	}

	// The DACL alone does not separate UAC's split tokens. An elevated host
	// and a medium-integrity process of the same user carry the same account
	// SID, so the grant above admits both, and the attach socket's only
	// gatekeeper is the permission on the directory holding it. A mandatory
	// label denying read-up, write-up and execute-up is what keeps the
	// unelevated half out of an elevated session.
	//
	// The label is this process's own level and no higher: a process may only
	// set a label it holds, so an elevated host labels the directory high and
	// an ordinary one labels it medium — in both cases, whatever a peer would
	// have to hold to be trusted with the session. Every directory passed
	// through this function is labelled, not only session directories.
	rid, err := tokenIntegrityRID(token)
	if err != nil {
		return fmt.Errorf("sessiondir: %w", err)
	}
	label, err := windows.SecurityDescriptorFromString(fmt.Sprintf("S:(ML;OICI;NRNWNX;;;S-1-16-%d)", rid))
	if err != nil {
		return fmt.Errorf("sessiondir: build integrity label S-1-16-%d: %w", rid, err)
	}
	sacl, _, err := label.SACL()
	if err != nil {
		return fmt.Errorf("sessiondir: integrity label S-1-16-%d has no SACL: %w", rid, err)
	}
	if sacl == nil {
		// x/sys reports a present-but-empty SACL as a nil ACL with no error,
		// and passing that on would ask SetNamedSecurityInfo to clear the
		// label rather than set one — the state this whole block exists to
		// prevent.
		return fmt.Errorf("sessiondir: integrity label S-1-16-%d parsed to an empty SACL", rid)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.LABEL_SECURITY_INFORMATION, nil, nil, nil, sacl); err != nil {
		return fmt.Errorf("sessiondir: set integrity label S-1-16-%d on %s: %w", rid, path, err)
	}
	return nil
}

// tokenIntegrityRID returns the RID of a token's integrity level — 0x1000
// low, 0x2000 medium, 0x3000 high, 0x4000 system — which is the last
// sub-authority of the SID in its TOKEN_MANDATORY_LABEL.
//
// A token whose level cannot be read is an error, not a reason to fall back:
// the caller creates the session directory and removes it again when securing
// fails, and an elevated session directory with no label is precisely the
// hole the label closes. Guessing medium would under-label an elevated
// session; guessing high would be rejected, since a process may only set a
// label it holds. Refusing to create the session is the only answer that
// cannot silently leave the socket open to the unelevated half of a split
// token.
func tokenIntegrityRID(token windows.Token) (uint32, error) {
	// The buffer holds a TOKEN_MANDATORY_LABEL followed by its SID; 64 bytes
	// covers the one-sub-authority integrity SIDs, and the loop resizes if
	// Windows ever wants more. It only repeats while the requested size grows
	// past what was offered, so it cannot spin.
	buf := make([]byte, 64)
	var n uint32
	for {
		err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &n)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || int(n) <= len(buf) {
			return 0, fmt.Errorf("read token integrity level: %w", err)
		}
		buf = make([]byte, n)
	}

	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	if sid == nil || !sid.IsValid() {
		return 0, errors.New("read token integrity level: no integrity SID on the token")
	}
	count := sid.SubAuthorityCount()
	if count == 0 {
		return 0, fmt.Errorf("read token integrity level: %s has no sub-authority to take the level from", sid)
	}
	return sid.SubAuthority(uint32(count) - 1), nil
}
