package sftp

// PermissionResult represents the user's response to a permission dialog
type PermissionResult int

const (
	PermissionDenied PermissionResult = iota
	PermissionAllowed
	PermissionAlwaysAllow
)

// PermissionChecker is called to check if an SFTP operation is allowed.
// Implementations can show UI dialogs, auto-allow, or deny based on policy.
type PermissionChecker interface {
	// CheckPermission returns the user's decision for the operation.
	// Returns error if the checker is unavailable (e.g., no display).
	CheckPermission(operation, path string) (PermissionResult, error)
}
