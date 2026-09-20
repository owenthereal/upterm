//go:build windows

package sessiondir

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
// low, 0x2000 medium, 0x3000 high, 0x4000 system — which is the level carried
// by the SID in its TOKEN_MANDATORY_LABEL.
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
	// The buffer holds a TOKEN_MANDATORY_LABEL followed by its SID. 64 bytes
	// is comfortably more than a one-sub-authority integrity SID needs, and
	// the loop resizes if Windows ever wants more; it only repeats while the
	// size asked for grows past what was offered, so it cannot spin.
	//
	// It is []uint64 and not the obvious []byte because of the cast below.
	// checkptr throws "misaligned pointer conversion" for a conversion to any
	// pointer-bearing type — TOKEN_MANDATORY_LABEL holds a *SID — whose
	// address is not aligned to that type (runtime/checkptr.go:19-21). A
	// constant-size []byte that does not escape is a stack array of alignment
	// one, so &buf[0] would satisfy that only by the luck of the frame
	// layout: the identical line in this package's test ran out of luck on
	// Windows CI while this one happened to pass. An element type of uint64
	// is aligned to at least a pointer on every platform Go builds for, so
	// the cast is correct by construction, on the stack or on the heap.
	buf := make([]uint64, 8)
	var n uint32
	for {
		err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel,
			(*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &n)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || int(n) <= len(buf)*8 {
			return 0, fmt.Errorf("read token integrity level: %w", err)
		}
		buf = make([]uint64, (int(n)+7)/8)
	}

	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	if sid == nil || !sid.IsValid() {
		return 0, errors.New("read token integrity level: no integrity SID on the token")
	}

	// The level comes out of the SID's string form, not out of
	// SubAuthority/SubAuthorityCount. Those call Win32 accessors that hand
	// back a raw address inside the buffer above, which x/sys converts
	// straight to a Go pointer (x/sys@v0.48.0 zsyscall_windows.go:950-961).
	// The buffer is Go memory, so -race's checkptr sees a pointer conjured
	// from a uintptr into an allocation it never came from and kills the
	// process — every Claim, not just a test. ConvertSidToStringSid returns
	// Windows-allocated memory instead, which checkptr does not police.
	text := sid.String()
	rid, ok := integrityRIDFromSID(text)
	if !ok {
		return 0, fmt.Errorf("read token integrity level: %q is not a mandatory label SID", text)
	}
	return rid, nil
}

// integrityRIDFromSID takes the level out of a mandatory label SID, whose
// string form is S-1-16-<rid> and nothing else.
//
// Anything else fails closed, for the same reason an unreadable token does: a
// user SID, a truncated one, a level too big for the field, or the empty
// string a failed String() returns is not a level, and labelling with a
// number guessed from one of those is how an elevated session ends up
// reachable from the unelevated half of a split token.
func integrityRIDFromSID(sid string) (uint32, bool) {
	rid, ok := strings.CutPrefix(sid, "S-1-16-")
	if !ok {
		return 0, false
	}
	level, err := strconv.ParseUint(rid, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(level), true
}
