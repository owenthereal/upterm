package upterm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	ApprovalRegisterRequest = "approval-register-v1@upterm"
	ApprovalStateRequest    = "approval-state-v1@upterm"
	ApprovalAnswerRequest   = "approval-answer-v1@upterm"
	MaxApprovalPayload      = 128 * 1024
)

// Subjects are byte slices so JSON preserves arbitrary SSH command/path bytes.
type ApprovalRequest struct {
	ID, Capability, Operation, Fingerprint string
	Subjects                               [][]byte
	DeadlineUnixMilli                      int64
}
type ApprovalState struct {
	Revision uint64
	Pending  uint32
	Current  *ApprovalRequest
}
type ApprovalAnswer struct{ ID, Decision string }

func decodeApproval(payload []byte, value any) error {
	if len(payload) == 0 || len(payload) > MaxApprovalPayload {
		return errors.New("invalid approval payload size")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing approval payload")
	}
	return nil
}
func approvalText(s string, max int, required bool) bool {
	return (!required || s != "") && len(s) <= max && utf8.ValidString(s)
}
func (r ApprovalRequest) validate() error {
	if !approvalText(r.ID, 128, true) || !approvalText(r.Fingerprint, 256, false) || r.DeadlineUnixMilli <= 0 {
		return errors.New("invalid approval identity/deadline")
	}
	capability, count := "", 1
	switch r.Operation {
	case "download", "upload", "delete", "mkdir", "rmdir", "setstat":
		capability = "sftp"
	case "rename", "symlink", "link":
		capability = "sftp"
		count = 2
	case "exec":
		capability = "exec"
	case "forward":
		capability = "forward"
		count = 2
	default:
		return errors.New("invalid approval operation")
	}
	if r.Capability != capability || len(r.Subjects) != count {
		return errors.New("invalid approval capability/subjects")
	}
	total := 0
	for _, subject := range r.Subjects {
		if subject == nil {
			return errors.New("invalid approval subject")
		}
		total += len(subject)
	}
	if total > 8192 {
		return errors.New("approval subjects too large")
	}
	return nil
}
func (s ApprovalState) validate() error {
	if s.Revision == 0 || s.Pending > 32 || (s.Pending == 0) != (s.Current == nil) {
		return errors.New("invalid approval state")
	}
	if s.Current != nil {
		return s.Current.validate()
	}
	return nil
}
func EncodeApprovalState(state ApprovalState) ([]byte, error) {
	if err := state.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(state)
	if len(payload) > MaxApprovalPayload {
		return nil, errors.New("approval payload too large")
	}
	return payload, err
}
func DecodeApprovalState(payload []byte) (ApprovalState, error) {
	// encoding/json also accepts numeric arrays and null for []byte. Decode
	// the wire elements as strings explicitly: v1 subjects are base64 only.
	var wire struct {
		Revision uint64
		Pending  uint32
		Current  *struct {
			ApprovalRequest
			Subjects []*string
		}
	}
	if err := decodeApproval(payload, &wire); err != nil {
		return ApprovalState{}, err
	}
	state := ApprovalState{Revision: wire.Revision, Pending: wire.Pending}
	if wire.Current != nil {
		request := wire.Current.ApprovalRequest
		for _, subject := range wire.Current.Subjects {
			if subject == nil {
				return ApprovalState{}, errors.New("invalid base64 approval subject")
			}
			raw, err := base64.StdEncoding.DecodeString(*subject)
			if err != nil {
				return ApprovalState{}, err
			}
			request.Subjects = append(request.Subjects, raw)
		}
		state.Current = &request
	}
	return state, state.validate()
}
func DecodeApprovalAnswer(payload []byte) (ApprovalAnswer, error) {
	var answer ApprovalAnswer
	if err := decodeApproval(payload, &answer); err != nil {
		return ApprovalAnswer{}, err
	}
	if !approvalText(answer.ID, 128, true) {
		return ApprovalAnswer{}, errors.New("invalid approval ID")
	}
	switch answer.Decision {
	case "deny", "connection", "guest":
		return answer, nil
	}
	return ApprovalAnswer{}, errors.New("invalid approval decision")
}
