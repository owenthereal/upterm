package internal

import (
	"fmt"

	"github.com/owenthereal/upterm/host/sftp"
)

// checkPermission prompts user for permission if needed
func (s *SFTPSession) checkPermission(operation, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Skip prompt if user already clicked "Always"
	if s.alwaysAllow {
		return nil
	}

	// No checker = auto-allow (headless/CI mode)
	if s.permissionChecker == nil {
		return nil
	}

	// Try to show permission dialog
	result, err := s.permissionChecker.CheckPermission(operation, path)
	if err != nil {
		// Checker unavailable (headless system)
		// Allow operation - connection-level consent is sufficient
		return nil
	}

	switch result {
	case sftp.PermissionAllowed:
		return nil
	case sftp.PermissionAlwaysAllow:
		s.alwaysAllow = true
		return nil
	default:
		return fmt.Errorf("permission denied by user")
	}
}
