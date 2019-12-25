package ftests

import (
	"strings"
	"testing"
)

func testHostFailToShareWithoutPrivateKey(t *testing.T, testServer TestServer) {
	h := &Host{
		Command: []string{"bash"},
	}
	err := h.Share(testServer.Addr(), testServer.SocketDir())
	if err == nil {
		t.Fatal("expect error")
	}

	if !strings.Contains(err.Error(), "Permission denied (publickey)") {
		t.Fatalf("expect permission denied error: %s", err)
	}
}
