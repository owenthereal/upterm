package ftests

import "testing"

func Test_HostFailToShareWithoutPrivateKey(t *testing.T) {
	h := &Host{
		Command:     []string{"bash"},
		PrivateKeys: []string{hostPrivateKey},
	}
	if err := h.Share(s.Addr(), s.SocketDir()); err != nil {
		t.Fatal(err)
	}
	defer h.Close()
}
