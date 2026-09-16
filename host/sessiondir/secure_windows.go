//go:build windows

package sessiondir

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// secureSessionDir gives the directory a DACL of its own: protected, so it
// inherits nothing from its parent, and granting full control to the current
// user and nobody else. Objects created inside — the sockets — inherit it.
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
	return nil
}
