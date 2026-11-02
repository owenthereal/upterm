package upterm

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApprovalProtocol(t *testing.T) {
	subjects := [][]byte{{0xff}, {0xfe}, []byte("�"), []byte(`\xff`), []byte("\x1b\n\x00"), []byte("second/path")}
	rendered := map[string]bool{}
	for _, subject := range subjects {
		text := strconv.QuoteToASCII(string(subject))
		require.False(t, rendered[text])
		rendered[text] = true
	}
	state := ApprovalState{Revision: 1, Pending: 1, Current: &ApprovalRequest{ID: "1", Capability: "sftp", Operation: "rename", Fingerprint: "SHA256:key", Subjects: subjects[:2], DeadlineUnixMilli: 1}}
	for _, pair := range [][][]byte{subjects[:2], subjects[2:4], subjects[4:]} {
		state.Current.Subjects = pair
		payload, err := EncodeApprovalState(state)
		require.NoError(t, err)
		got, err := DecodeApprovalState(payload)
		require.NoError(t, err)
		require.Equal(t, pair, got.Current.Subjects)
		require.NotEqual(t, strconv.QuoteToASCII(string(pair[0])), strconv.QuoteToASCII(string(pair[1])))
	}
	raw, err := json.Marshal(state)
	require.NoError(t, err)
	for _, payload := range [][]byte{nil, []byte(`{}`), []byte(`{"Revision":1,"Pending":1,"Current":null}`), []byte(strings.Replace(string(raw), `"sftp"`, `"exec"`, 1)), []byte(strings.Replace(string(raw), `"Subjects":[`, `"Subjects":["%%%",`, 1)), []byte(strings.Replace(string(raw), `"Subjects":[`, `"Subjects":[[255],`, 1)), []byte(strings.Replace(string(raw), `"Subjects":[`, `"Subjects":[null,`, 1)), append(raw, raw...), []byte(strings.Repeat(" ", MaxApprovalPayload+1))} {
		_, err := DecodeApprovalState(payload)
		require.Error(t, err, string(payload[:min(len(payload), 100)]))
	}
	state.Current.Fingerprint = ""
	_, err = EncodeApprovalState(state)
	require.NoError(t, err)
	state.Current.Subjects = [][]byte{make([]byte, 8192), []byte{}}
	boundary, err := EncodeApprovalState(state)
	require.NoError(t, err)
	_, err = DecodeApprovalState(boundary)
	require.NoError(t, err)
	state.Current.Subjects = [][]byte{make([]byte, 8192), []byte("x")}
	oversized, _ := json.Marshal(state)
	_, err = DecodeApprovalState(oversized)
	require.Error(t, err)
	state.Current.Subjects = [][]byte{make([]byte, 8192), []byte("x")}
	_, err = EncodeApprovalState(state)
	require.Error(t, err)
	state.Current.Subjects = [][]byte{[]byte("only")}
	_, err = EncodeApprovalState(state)
	require.Error(t, err)
	for _, subject := range []string{`[255]`, `null`, `"%%%"`} {
		_, err := DecodeApprovalState([]byte(`{"Revision":1,"Pending":1,"Current":{"ID":"1","Capability":"exec","Operation":"exec","Subjects":[` + subject + `],"DeadlineUnixMilli":1}}`))
		require.Error(t, err)
	}
	for _, decision := range []string{"deny", "connection", "guest"} {
		got, err := DecodeApprovalAnswer([]byte(`{"ID":"1","Decision":"` + decision + `"}`))
		require.NoError(t, err)
		require.Equal(t, decision, got.Decision)
	}
	for _, payload := range []string{`{}`, `{"ID":"1","Decision":"yes"}`, `{"ID":"1","Decision":"guest","Subjects":["x"]}`, `{"ID":"","Decision":"deny"}`} {
		_, err := DecodeApprovalAnswer([]byte(payload))
		require.Error(t, err)
	}
}

// Who is asking travels with the request: the host's own allowlist label for
// the guest's key, or that the session has no allowlist at all. Both are left
// out of the payload when unset, as they are by a daemon that sends neither.
func TestApprovalGuest(t *testing.T) {
	state := ApprovalState{Revision: 1, Pending: 1, Current: &ApprovalRequest{ID: "1", Capability: "exec", Operation: "exec", Fingerprint: "SHA256:key", Subjects: [][]byte{[]byte("bash")}, DeadlineUnixMilli: 1}}
	payload, err := EncodeApprovalState(state)
	require.NoError(t, err)
	require.NotContains(t, string(payload), "Guest")
	require.NotContains(t, string(payload), "Unlisted")
	got, err := DecodeApprovalState(payload)
	require.NoError(t, err)
	require.Empty(t, got.Current.Guest)
	require.False(t, got.Current.Unlisted)

	for _, current := range []ApprovalRequest{
		{Guest: "alice (github:alice)"},
		{Guest: strings.Repeat("é", MaxApprovalGuest/2)},
		{Unlisted: true},
	} {
		request := *state.Current
		request.Guest, request.Unlisted = current.Guest, current.Unlisted
		payload, err := EncodeApprovalState(ApprovalState{Revision: 1, Pending: 1, Current: &request})
		require.NoError(t, err)
		got, err := DecodeApprovalState(payload)
		require.NoError(t, err)
		require.Equal(t, request, *got.Current)
	}
	for _, guest := range []string{strings.Repeat("a", MaxApprovalGuest+1), "\xff"} {
		request := *state.Current
		request.Guest = guest
		_, err := EncodeApprovalState(ApprovalState{Revision: 1, Pending: 1, Current: &request})
		require.Error(t, err)
	}
}
