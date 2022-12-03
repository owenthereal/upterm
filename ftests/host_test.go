package ftests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func testHostClientCallback(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	jch := make(chan *api.Client)
	lch := make(chan *api.Client)

	adminSockDir, err := newAdminSocketDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(adminSockDir)

	adminSocketFile := filepath.Join(adminSockDir, "upterm.sock")

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' BASH_SILENCE_DEPRECATION_WARNING=1 bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
		ClientJoinedCallback: func(c *api.Client) {
			jch <- c
		},
		ClientLeftCallback: func(c *api.Client) {
			lch <- c
		},
	}

	if err := h.Share(hostShareURL); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// verify admin server
	session := getAndVerifySession(t, adminSocketFile, hostShareURL, hostNodeAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	if err := c.JoinWithContext(ctx, session, clientJoinURL); err != nil {
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
		if cc.Id == "" {
			t.Fatal("client id can't be empty")
		}

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
		if os.Getenv("MUTE_FLAKY_TESTS") != "" {
			log.Error("FLAKY_TEST: client left callback is not called")
		} else {
			t.Fatal("client left callback is not called")
		}
	}
}

func testHostSessionCreatedCallback(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	h := &Host{
		Command:      []string{"bash", "--norc"},
		ForceCommand: []string{"vim"},
		PrivateKeys:  []string{HostPrivateKey},
		SessionCreatedCallback: func(session *api.GetSessionResponse) error {
			if want, got := []string{"bash", "--norc"}, session.Command; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}
			if want, got := []string{"vim"}, session.ForceCommand; !cmp.Equal(want, got) {
				t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
			}

			checkSessionPayload(t, session, hostShareURL, hostNodeAddr)
			return nil
		},
	}

	if err := h.Share(hostShareURL); err != nil {
		t.Fatal(err)
	}
	defer h.Close()
}

func testHostFailToShareWithoutPrivateKey(t *testing.T, hostShareURL, hostNodeAddr, clientJoinURL string) {
	h := &Host{
		Command: []string{"bash"},
	}
	err := h.Share(hostShareURL)
	if err == nil {
		t.Fatal("expect error")
	}

	if !strings.Contains(err.Error(), "Permission denied (publickey)") {
		t.Fatalf("expect permission denied error: %s", err)
	}
}
