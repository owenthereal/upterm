package command

import (
	"fmt"
	"strings"
	"sync"

	"github.com/ncruces/zenity"
	"github.com/owenthereal/upterm/host/sftp"
	"github.com/owenthereal/upterm/utils"
)

// DialogPermissionChecker shows GUI dialogs for permission prompts.
type DialogPermissionChecker struct {
	// allowedSessions tracks SSH sessions where user clicked "Allow All".
	// All operations in these sessions are auto-allowed.
	allowedSessions sync.Map // map[sessionID]struct{}

	// allowedFiles tracks files where user clicked "Allow" (per session).
	// All operations on these files are auto-allowed for that session.
	// Key format: "sessionID:path"
	allowedFiles sync.Map // map[string]struct{}
}

// CheckPermission shows a dialog for the operation.
// For two-path operations (rename, symlink, link), both source and target paths are passed.
func (d *DialogPermissionChecker) CheckPermission(op sftp.Operation, client sftp.ClientInfo, paths ...string) (sftp.PermissionResult, error) {
	if len(paths) == 0 {
		return sftp.PermissionDenied, fmt.Errorf("no path provided")
	}

	// Auto-allow if user clicked "Allow All" for this session
	if d.isSessionAllowed(client.SessionID) {
		return sftp.PermissionAllowed, nil
	}

	// Auto-allow if user clicked "Allow" for all involved paths in this session
	allPathsAllowed := true
	for _, p := range paths {
		if !d.isFileAllowed(client.SessionID, p) {
			allPathsAllowed = false
			break
		}
	}
	if allPathsAllowed {
		return sftp.PermissionAllowed, nil
	}

	result, err := d.showDialog(op, client, paths)

	// Track based on user's choice
	switch result {
	case sftp.PermissionAlwaysAllow:
		// "Allow All" - allow all operations in this session
		d.allowSession(client.SessionID)
	case sftp.PermissionAllowed:
		// "Allow" - allow all operations on these paths in this session
		for _, p := range paths {
			d.allowFile(client.SessionID, p)
		}
	}

	return result, err
}

func (d *DialogPermissionChecker) allowSession(sessionID string) {
	d.allowedSessions.Store(sessionID, struct{}{})
}

func (d *DialogPermissionChecker) isSessionAllowed(sessionID string) bool {
	_, ok := d.allowedSessions.Load(sessionID)
	return ok
}

func (d *DialogPermissionChecker) allowFile(sessionID, path string) {
	key := sessionID + ":" + path
	d.allowedFiles.Store(key, struct{}{})
}

func (d *DialogPermissionChecker) isFileAllowed(sessionID, path string) bool {
	key := sessionID + ":" + path
	_, ok := d.allowedFiles.Load(key)
	return ok
}

// ClearSession removes cached permissions for the given session.
func (d *DialogPermissionChecker) ClearSession(sessionID string) {
	// Remove session-level permission
	d.allowedSessions.Delete(sessionID)

	// Remove all file-level permissions for this session
	prefix := sessionID + ":"
	d.allowedFiles.Range(func(key, _ any) bool {
		if k, ok := key.(string); ok && strings.HasPrefix(k, prefix) {
			d.allowedFiles.Delete(key)
		}
		return true
	})
}

func (d *DialogPermissionChecker) showDialog(op sftp.Operation, client sftp.ClientInfo, paths []string) (sftp.PermissionResult, error) {
	title := "Upterm File Transfer"

	// Format client identifier
	clientID := "unknown"
	if client.Fingerprint != "" {
		clientID = client.Fingerprint
	}

	// Use shortened paths for user-friendly display (e.g., ~/foo instead of /Users/name/foo)
	displayPath := utils.ShortenHomePath(paths[0])
	var displayTarget string
	if len(paths) > 1 {
		displayTarget = utils.ShortenHomePath(paths[1])
	}

	var msg string
	switch op {
	case sftp.OpDownload:
		msg = fmt.Sprintf("Client [%s] wants to download:\n%s", clientID, displayPath)
	case sftp.OpUpload:
		msg = fmt.Sprintf("Client [%s] wants to upload:\n%s", clientID, displayPath)
	case sftp.OpDelete, sftp.OpRmdir:
		msg = fmt.Sprintf("Client [%s] wants to delete:\n%s", clientID, displayPath)
	case sftp.OpMkdir:
		msg = fmt.Sprintf("Client [%s] wants to create directory:\n%s", clientID, displayPath)
	case sftp.OpRename:
		if displayTarget != "" {
			msg = fmt.Sprintf("Client [%s] wants to rename:\n%s → %s", clientID, displayPath, displayTarget)
		} else {
			msg = fmt.Sprintf("Client [%s] wants to rename:\n%s", clientID, displayPath)
		}
	case sftp.OpSymlink:
		if displayTarget != "" {
			msg = fmt.Sprintf("Client [%s] wants to create symlink:\n%s → %s", clientID, displayPath, displayTarget)
		} else {
			msg = fmt.Sprintf("Client [%s] wants to create symlink:\n%s", clientID, displayPath)
		}
	case sftp.OpLink:
		if displayTarget != "" {
			msg = fmt.Sprintf("Client [%s] wants to create hard link:\n%s → %s", clientID, displayPath, displayTarget)
		} else {
			msg = fmt.Sprintf("Client [%s] wants to create hard link:\n%s", clientID, displayPath)
		}
	case sftp.OpSetstat:
		msg = fmt.Sprintf("Client [%s] wants to modify file attributes:\n%s", clientID, displayPath)
	default:
		msg = fmt.Sprintf("Client [%s] wants to %s:\n%s", clientID, op.String(), displayPath)
	}

	// Show question dialog with Allow/Allow All/Deny buttons
	err := zenity.Question(msg,
		zenity.Title(title),
		zenity.OKLabel("Allow"),
		zenity.CancelLabel("Deny"),
		zenity.ExtraButton("Allow All"),
	)

	if err == nil {
		return sftp.PermissionAllowed, nil
	}
	if err == zenity.ErrExtraButton {
		return sftp.PermissionAlwaysAllow, nil
	}
	if err == zenity.ErrCanceled {
		return sftp.PermissionDenied, nil
	}

	// Other error (e.g., zenity not installed, no display)
	return sftp.PermissionDenied, err
}

// AutoAllowPermissionChecker always allows operations (for --accept mode or testing).
type AutoAllowPermissionChecker struct{}

// CheckPermission always returns PermissionAllowed.
func (a *AutoAllowPermissionChecker) CheckPermission(op sftp.Operation, client sftp.ClientInfo, paths ...string) (sftp.PermissionResult, error) {
	return sftp.PermissionAllowed, nil
}

// ClearSession is a no-op since AutoAllowPermissionChecker doesn't track sessions.
func (a *AutoAllowPermissionChecker) ClearSession(sessionID string) {}
