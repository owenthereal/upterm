package ftests

import (
	"strings"
	"testing"
)

func Test_HostFailToShareWithoutPrivateKey(t *testing.T) {
	h := &Host{
		Command: []string{"bash"},
	}
	err := h.Share(s.Addr(), s.SocketDir())
	if err == nil {
		t.Fatal("expect error")
	}

	if !strings.Contains(err.Error(), "Permission denied (publickey)") {
		t.Fatalf("expect permission denied error: %s", err)
	}
}
