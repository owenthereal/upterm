package sftp

// Operation represents an SFTP operation type
type Operation int

const (
	OpDownload Operation = iota
	OpUpload
	OpDelete
	OpMkdir
	OpRmdir
	OpRename
	OpSymlink
	OpLink
	OpSetstat
)

// String returns a human-readable name for the operation
func (o Operation) String() string {
	switch o {
	case OpDownload:
		return "download"
	case OpUpload:
		return "upload"
	case OpDelete:
		return "delete"
	case OpMkdir:
		return "mkdir"
	case OpRmdir:
		return "rmdir"
	case OpRename:
		return "rename"
	case OpSymlink:
		return "symlink"
	case OpLink:
		return "link"
	case OpSetstat:
		return "setstat"
	default:
		return "unknown"
	}
}

// PermissionResult represents the user's response to a permission dialog
type PermissionResult int

const (
	PermissionDenied PermissionResult = iota
	PermissionAllowed
	PermissionAlwaysAllow
)

// ClientInfo contains information about the SFTP client
type ClientInfo struct {
	Fingerprint string // SSH public key fingerprint (e.g., "SHA256:...")
	SessionID   string // SSH session ID (identifies a single scp/sftp command)
}

// PermissionChecker is called to check if an SFTP operation is allowed.
// Implementations can show UI dialogs, auto-allow, or deny based on policy.
type PermissionChecker interface {
	// CheckPermission returns the user's decision for the operation.
	// Returns error if the checker is unavailable (e.g., no display).
	CheckPermission(op Operation, path string, client ClientInfo) (PermissionResult, error)

	// ClearSession removes any cached permissions for the given session.
	// Called when an SFTP session ends to prevent memory leaks.
	ClearSession(sessionID string)
}
