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
func (d *DialogPermissionChecker) CheckPermission(op sftp.Operation, path string, client sftp.ClientInfo) (sftp.PermissionResult, error) {
	// Auto-allow if user clicked "Allow All" for this session
	if d.isSessionAllowed(client.SessionID) {
		return sftp.PermissionAllowed, nil
	}

	// Auto-allow if user clicked "Allow" for this file in this session
	if d.isFileAllowed(client.SessionID, path) {
		return sftp.PermissionAllowed, nil
	}

	result, err := showPermissionDialog(op, path, client)

	// Track based on user's choice
	switch result {
	case sftp.PermissionAlwaysAllow:
		// "Allow All" - allow all operations in this session
		d.allowSession(client.SessionID)
	case sftp.PermissionAllowed:
		// "Allow" - allow all operations on this file in this session
		d.allowFile(client.SessionID, path)
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

// AutoAllowPermissionChecker always allows operations (for --accept mode or testing).
type AutoAllowPermissionChecker struct{}

// CheckPermission always returns SFTPPermissionAllowed.
func (a *AutoAllowPermissionChecker) CheckPermission(op sftp.Operation, path string, client sftp.ClientInfo) (sftp.PermissionResult, error) {
	return sftp.PermissionAllowed, nil
}

// ClearSession is a no-op since AutoAllowPermissionChecker doesn't track sessions.
func (a *AutoAllowPermissionChecker) ClearSession(sessionID string) {}

func showPermissionDialog(op sftp.Operation, path string, client sftp.ClientInfo) (sftp.PermissionResult, error) {
	title := "Upterm File Transfer"

	// Format client identifier
	clientID := "unknown"
	if client.Fingerprint != "" {
		clientID = client.Fingerprint
	}

	// Use shortened path for user-friendly display (e.g., ~/foo instead of /Users/name/foo)
	displayPath := utils.ShortenHomePath(path)

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
		msg = fmt.Sprintf("Client [%s] wants to rename:\n%s", clientID, displayPath)
	case sftp.OpSymlink:
		msg = fmt.Sprintf("Client [%s] wants to create symlink:\n%s", clientID, displayPath)
	case sftp.OpLink:
		msg = fmt.Sprintf("Client [%s] wants to create hard link:\n%s", clientID, displayPath)
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
