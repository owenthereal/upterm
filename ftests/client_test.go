package ftests

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jingweno/upterm/host"
)

func testClientNonExistingSession(t *testing.T, hostURL, nodeAddr string) {
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
	if want, got := h.SessionID, session.SessionID; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := hostURL, session.Host; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := nodeAddr, session.NodeAddr; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	hostInputCh <- "echo hello"
	if want, got := "echo hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	session.SessionID = "not-existance" // set session ID to non-existance
	err = c.Join(session, hostURL)

	// Unfortunately there is no explicit error to the client.
	// But ssh handshake fails with the connection closed
	if want, got := "ssh: handshake failed:", err.Error(); !strings.Contains(got, want) {
		t.Fatalf("Unexpected error, want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
}

func testClientAttachHostWithSameCommand(t *testing.T, hostURL, nodeAddr string) {
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
	if want, got := h.SessionID, session.SessionID; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := hostURL, session.Host; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := nodeAddr, session.NodeAddr; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	if err := c.Join(session, hostURL); err != nil {
		t.Fatal(err)
	}

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)

	// host input
	hostInputCh <- "echo hello"
	if want, got := "echo hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	// client output
	if want, got := "echo hello", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	// client input
	remoteInputCh <- "echo hello again"
	if want, got := "echo hello again", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello again", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	// host output
	// host should link to remote with the same input/output
	if want, got := "echo hello again", scan(hostScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello again", scan(hostScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
}

func testClientAttachHostWithDifferentCommand(t *testing.T, hostURL string, nodeAddr string) {
	adminSockDir, err := newAdminSocketDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(adminSockDir)

	adminSocketFile := filepath.Join(adminSockDir, "upterm.sock")

	h := &Host{
		Command:                  []string{"bash", "-c", "PS1='' bash --norc"},
		ForceCommand:             []string{"bash", "-c", "PS1='' bash --norc"},
		PrivateKeys:              []string{HostPrivateKey},
		AdminSocketFile:          adminSocketFile,
		PermittedClientPublicKey: ClientPublicKeyContent,
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
	if want, got := h.SessionID, session.SessionID; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := hostURL, session.Host; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := nodeAddr, session.NodeAddr; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	hostInputCh <- "echo hello"
	if want, got := "echo hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	if err := c.Join(session, hostURL); err != nil {
		t.Fatal(err)
	}

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)
	time.Sleep(1 * time.Second) // HACK: wait for ssh stdin/stdout to fully attach

	remoteInputCh <- "echo hello again"
	if want, got := "echo hello again", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello again", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	// host shouldn't be linked to remote
	hostInputCh <- "echo hello"
	if want, got := "echo hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
}

func testClientAttachReadOnly(t *testing.T, hostURL, nodeAddr string) {
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
		ReadOnly:                 true,
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
	if want, got := h.SessionID, session.SessionID; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := hostURL, session.Host; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := nodeAddr, session.NodeAddr; want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	// verify input/output
	hostInputCh, hostOutputCh := h.InputOutput()
	hostScanner := scanner(hostOutputCh)

	c := &Client{
		PrivateKeys: []string{ClientPrivateKey},
	}
	if err := c.Join(session, hostURL); err != nil {
		t.Fatal(err)
	}

	remoteInputCh, remoteOutputCh := c.InputOutput()
	remoteScanner := scanner(remoteOutputCh)

	// client output
	// client should get "welcome message"
	// \n
	// === Attached to read-only session ===
	// \n
	if want, got := "", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "=== Attached to read-only session ===", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	// host input should still work
	hostInputCh <- "echo hello"
	if want, got := "echo hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", scan(hostScanner); want != got {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	// client input should be disabled
	remoteInputCh <- "echo hello again"
	// client should read what was sent by hostInputCh and not what was sent on remoteInputCh
	if want, got := "echo hello", scan(remoteScanner); want != got {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	// host output
	// host should link to remote with the same input/output
	// scan will timeout as there shouldn't be anything to scan
	// client didn't insert anything
	go func() {
		if want, got := "", scan(hostScanner); want != got {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}
		if want, got := "hello again", scan(hostScanner); want != got {
			t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
		}
	}()

	select {
	case <-time.After(time.Second * 1):
		log.Println("Timeout hit..")
		return
	}

}

func newAdminSocketDir() (string, error) {
	return ioutil.TempDir("", "upterm")
}
