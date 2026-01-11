package command

import (
	"fmt"

	"github.com/ncruces/zenity"
	"github.com/owenthereal/upterm/host/sftp"
)

// DialogPermissionChecker shows GUI dialogs for permission prompts.
type DialogPermissionChecker struct{}

// CheckPermission shows a dialog for the operation.
func (d *DialogPermissionChecker) CheckPermission(operation, path string) (sftp.PermissionResult, error) {
	return showPermissionDialog(operation, path)
}

// AutoAllowPermissionChecker always allows operations (for --accept mode or testing).
type AutoAllowPermissionChecker struct{}

// CheckPermission always returns SFTPPermissionAllowed.
func (a *AutoAllowPermissionChecker) CheckPermission(operation, path string) (sftp.PermissionResult, error) {
	return sftp.PermissionAllowed, nil
}

func showPermissionDialog(operation, path string) (sftp.PermissionResult, error) {
	title := "Upterm File Transfer"

	var msg string
	switch operation {
	case "download":
		msg = fmt.Sprintf("Client wants to download:\n%s", path)
	case "upload":
		msg = fmt.Sprintf("Client wants to upload:\n%s", path)
	case "delete", "rmdir":
		msg = fmt.Sprintf("Client wants to delete:\n%s", path)
	case "mkdir":
		msg = fmt.Sprintf("Client wants to create directory:\n%s", path)
	case "rename":
		msg = fmt.Sprintf("Client wants to rename:\n%s", path)
	case "symlink":
		msg = fmt.Sprintf("Client wants to create symlink:\n%s", path)
	case "setstat":
		msg = fmt.Sprintf("Client wants to modify file attributes:\n%s", path)
	default:
		msg = fmt.Sprintf("Client wants to %s:\n%s", operation, path)
	}

	// Show question dialog with Allow/Deny/Always buttons
	err := zenity.Question(msg,
		zenity.Title(title),
		zenity.OKLabel("Allow"),
		zenity.CancelLabel("Deny"),
		zenity.ExtraButton("Always Allow"),
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
