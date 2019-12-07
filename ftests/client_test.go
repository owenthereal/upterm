package ftests

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_ClientAttachHostWithSameCommand(t *testing.T) {
	h := &Host{
		Command:     []string{"bash"},
		PrivateKeys: []string{hostPrivateKey},
	}
	if err := h.Share(s.Addr(), s.SocketDir()); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	hostInputCh, hostOutputCh := h.InputOutput()

	<-hostOutputCh // discard prompt, e.g. bash-5.0$

	hostInputCh <- "echo hello"
	if want, got := "echo hello", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	c := &Client{}
	if err := c.Join(h.SessionID(), s.Addr()); err != nil {
		t.Fatal(err)
	}

	remoteInputCh, remoteOutputCh := c.InputOutput()

	<-remoteOutputCh // discard cached prompt, e.g. bash-5.0$
	<-remoteOutputCh // discard prompt, e.g. bash-5.0$

	remoteInputCh <- "echo hello again"
	if want, got := "echo hello again", <-remoteOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello again", <-remoteOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	<-hostOutputCh // discard prompt, e.g. bash-5.0$
	// host should link to remote with the same input/output
	if want, got := "echo hello again", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello again", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
}

func Test_ClientAttachHostWithDifferentCommand(t *testing.T) {
	h := &Host{
		Command:     []string{"bash"},
		JoinCommand: []string{"bash"},
		PrivateKeys: []string{hostPrivateKey},
	}
	if err := h.Share(s.Addr(), s.SocketDir()); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	hostInputCh, hostOutputCh := h.InputOutput()

	<-hostOutputCh // discard prompt, e.g. bash-5.0$

	hostInputCh <- "echo hello"
	if want, got := "echo hello", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}

	c := &Client{}
	if err := c.Join(h.SessionID(), s.Addr()); err != nil {
		t.Fatal(err)
	}

	remoteInputCh, remoteOutputCh := c.InputOutput()

	<-remoteOutputCh // discard prompt, e.g. bash-5.0$

	remoteInputCh <- "echo hello again"
	if want, got := "echo hello again", <-remoteOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello again", <-remoteOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%q got=%q:\n%s", want, got, cmp.Diff(want, got))
	}

	<-hostOutputCh // discard prompt, e.g. bash-5.0$

	// host shouldn't be linked to remote
	hostInputCh <- "echo hello"
	if want, got := "echo hello", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
	if want, got := "hello", <-hostOutputCh; !strings.Contains(got, want) {
		t.Fatalf("want=%s got=%s:\n%s", want, got, cmp.Diff(want, got))
	}
}
