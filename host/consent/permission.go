// Package consent implements capability-scoped, session-lifetime permission policy.
package consent

import (
	"context"
	"errors"
	"time"
)

// Capability is an independently granted class of guest operations.
type Capability string

const (
	CapabilitySFTP    Capability = "sftp"
	CapabilityExec    Capability = "exec"
	CapabilityForward Capability = "forward"
)

// Operation identifies the operation presented for review.
type Operation string

const (
	OpDownload Operation = "download"
	OpUpload   Operation = "upload"
	OpDelete   Operation = "delete"
	OpMkdir    Operation = "mkdir"
	OpRmdir    Operation = "rmdir"
	OpRename   Operation = "rename"
	OpSymlink  Operation = "symlink"
	OpLink     Operation = "link"
	OpSetstat  Operation = "setstat"
	OpExec     Operation = "exec"
	OpForward  Operation = "forward"
)

// Capability returns the operation's capability, or the empty string if invalid.
func (o Operation) Capability() Capability {
	switch o {
	case OpDownload, OpUpload, OpDelete, OpMkdir, OpRmdir, OpRename, OpSymlink, OpLink, OpSetstat:
		return CapabilitySFTP
	case OpExec:
		return CapabilityExec
	case OpForward:
		return CapabilityForward
	default:
		return ""
	}
}

// ClientInfo identifies an authenticated guest and its SSH connection.
// Fingerprint must come from the recovered guest key, never a relay certificate.
type ClientInfo struct{ Fingerprint, ConnectionID string }

// Decision specifies the lifetime and scope of an approval.
type Decision uint8

const (
	Deny Decision = iota
	AllowConnection
	AllowGuest
)

const (
	PermissionTimeout       = 60 * time.Second
	MaxPending              = 32
	MaxWaiters              = 256
	MaxWaitersPerConnection = 32
	MaxWaitersPerFlight     = 64
	MaxSubjectBytes         = 8192
)

var (
	ErrUnavailable     = errors.New("consent unavailable")
	ErrDenied          = errors.New("consent denied")
	ErrTimeout         = errors.New("consent timeout")
	ErrCanceled        = errors.New("consent canceled")
	ErrOverloaded      = errors.New("consent overloaded")
	ErrSubjectTooLarge = errors.New("consent subject too large")
	ErrStale           = errors.New("stale consent request")
)

// PermissionChecker checks consent after callers enforce hard policy and pregrants.
// Implementations must honor context cancellation. Callers must also reject an
// allowed result returned after cancellation or expiry of the permission context.
type PermissionChecker interface {
	CheckPermission(context.Context, Operation, ClientInfo, ...string) (Decision, error)
	ClearConnection(string)
}

// Prompt is a complete request for review. Subjects retain their raw bytes;
// presentation code must escape untrusted text without concealing differences.
type Prompt struct {
	ID        string
	Operation Operation
	Client    ClientInfo
	Subjects  []string
	Deadline  time.Time
}

// Prompter owns presentation on a capable local primary. It must honor context
// cancellation, which invalidates the prompt and its ID.
type Prompter interface {
	Prompt(context.Context, Prompt) (Decision, error)
}
