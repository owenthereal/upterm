package ftests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jingweno/upterm/host"
	"github.com/jingweno/upterm/host/api"
	"github.com/jingweno/upterm/host/api/swagger/models"
	"github.com/jingweno/upterm/utils"
	"golang.org/x/crypto/ssh"
)

func testHostClientCallback(t *testing.T, hostURL, nodeAddr string) {
	jch := make(chan api.Client)
	lch := make(chan api.Client)

	adminSockDir, err := newAdminSocketDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(adminSockDir)

	adminSocketFile := filepath.Join(adminSockDir, "upterm.sock")

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ClientJoinedCallback: func(c api.Client) {
			jch <- c
		},
		ClientLeftCallback: func(c api.Client) {
			lch <- c
		},
	}

	if err := h.Share(hostURL); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// verify admin server
	adminClient := host.AdminClient(adminSocketFile)
	resp, err := adminClient.GetSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	session := resp.GetPayload()
	checkSessionPayload(t, session, hostURL, nodeAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	if err := c.JoinWithContext(ctx, session, hostURL); err != nil {
		t.Fatal(err)
	}

	var clientID string
	select {
	case cc := <-jch:
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
		if err != nil {
			t.Fatal(err)
		}

		if cc.Id == "" {
			t.Fatal("client id can't be empty")
		}

		clientID = cc.Id

		if diff := cmp.Diff(utils.FingerprintSHA256(pk), cc.PublicKeyFingerprint); diff != "" {
			t.Fatal(diff)
		}

		if diff := cmp.Diff("SSH-2.0-Go", cc.Version); diff != "" {
			t.Fatal(diff)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client joined callback is not called")
	}

	// client leaves
	cancel()
	c.Close()

	select {
	case cc := <-lch:
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ClientPublicKeyContent))
		if err != nil {
			t.Fatal(err)
		}

		if diff := cmp.Diff(clientID, cc.Id); diff != "" {
			t.Fatal(diff)
		}

		if diff := cmp.Diff(utils.FingerprintSHA256(pk), cc.PublicKeyFingerprint); diff != "" {
			t.Fatal(diff)
		}

		if diff := cmp.Diff("SSH-2.0-Go", cc.Version); diff != "" {
			t.Fatal(diff)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client left callback is not called")
	}
}

func testHostSessionCreatedCallback(t *testing.T, hostURL, nodeAddr string) {
	h := &Host{
		Command:      []string{"bash", "--norc"},
		ForceCommand: []string{"vim"},
		PrivateKeys:  []string{HostPrivateKey},
		SessionCreatedCallback: func(session *models.APIGetSessionResponse) error {
			if want, got := []string{"bash", "--norc"}, session.Command; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}
			if want, got := []string{"vim"}, session.ForceCommand; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}

			checkSessionPayload(t, session, hostURL, nodeAddr)
			return nil
		},
	}

	if err := h.Share(hostURL); err != nil {
		t.Fatal(err)
	}
	defer h.Close()
}

func testHostFailToShareWithoutPrivateKey(t *testing.T, hostURL, nodeAddr string) {
	h := &Host{
		Command: []string{"bash"},
	}
	err := h.Share(hostURL)
	if err == nil {
		t.Fatal("expect error")
	}

	if !strings.Contains(err.Error(), "Permission denied (publickey)") {
		t.Fatalf("expect permission denied error: %s", err)
	}
}
