package ftests

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/jingweno/upterm/host/api/swagger/models"
	"github.com/rs/xid"
)

func testWebsocketHost(t *testing.T, testServer TestServer) {

}

func testHostSessionCreatedCallback(t *testing.T, testServer TestServer) {
	sessionID := xid.New().String()
	h := &Host{
		Command:      []string{"bash", "--norc"},
		ForceCommand: []string{"vim"},
		PrivateKeys:  []string{HostPrivateKey},
		SessionID:    sessionID,
		SessionCreatedCallback: func(session *models.APIGetSessionResponse) error {
			if want, got := []string{"bash", "--norc"}, session.Command; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}
			if want, got := []string{"vim"}, session.ForceCommand; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}
			if want, got := testServer.Addr(), session.Host; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}
			if want, got := testServer.NodeAddr(), session.NodeAddr; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}
			if want, got := sessionID, session.SessionID; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}

			return nil
		},
	}

	if err := h.Share(testServer.Addr()); err != nil {
		t.Fatal(err)
	}
	defer h.Close()
}

func testHostFailToShareWithoutPrivateKey(t *testing.T, testServer TestServer) {
	h := &Host{
		Command: []string{"bash"},
	}
	err := h.Share(testServer.Addr())
	if err == nil {
		t.Fatal("expect error")
	}

	if !strings.Contains(err.Error(), "Permission denied (publickey)") {
		t.Fatalf("expect permission denied error: %s", err)
	}
}
