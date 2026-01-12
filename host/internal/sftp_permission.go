package internal

import (
	"fmt"

	"github.com/owenthereal/upterm/host/sftp"
)

// checkPermission prompts user for permission if needed
func (s *SFTPSession) checkPermission(op sftp.Operation, path string) error {
	// No checker = auto-allow (headless/CI mode)
	if s.permissionChecker == nil {
		return nil
	}

	// Check permission (the checker handles caching of "Allow All" decisions)
	result, err := s.permissionChecker.CheckPermission(op, path, s.clientInfo)
	if err != nil {
		// Checker unavailable (headless system)
		// Allow operation - connection-level consent is sufficient
		return nil
	}

	if result == sftp.PermissionDenied {
		return fmt.Errorf("permission denied by user")
	}
	return nil
}
