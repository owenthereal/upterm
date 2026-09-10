package command

import (
	"testing"
	"time"

	"github.com/owenthereal/upterm/server"
	"github.com/stretchr/testify/require"
)

func TestFrontDoorFlags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		env     bool
		stock   bool
		timeout time.Duration
	}{
		{name: "defaults", timeout: 60 * time.Second},
		{name: "flags", args: []string{"--stock-ssh", "--handshake-timeout=8s"}, stock: true, timeout: 8 * time.Second},
		{name: "environment", env: true, stock: true, timeout: 12 * time.Second},
		{name: "flag overrides environment", env: true, args: []string{"--stock-ssh=false", "--handshake-timeout=4s"}, timeout: 4 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("UPTERMD_STOCK_SSH", "false")
			t.Setenv("UPTERMD_HANDSHAKE_TIMEOUT", "")
			if tc.env {
				t.Setenv("UPTERMD_STOCK_SSH", "true")
				t.Setenv("UPTERMD_HANDSHAKE_TIMEOUT", "12s")
			}
			cmd := Root()
			require.NoError(t, cmd.ParseFlags(tc.args))
			var opt server.Opt
			require.NoError(t, unmarshalFlags(cmd, &opt))
			require.Equal(t, tc.stock, opt.StockSSH)
			require.Equal(t, tc.timeout, opt.HandshakeTimeout)
		})
	}
}

func TestNegativeHandshakeTimeout(t *testing.T) {
	cmd := Root()
	require.NoError(t, cmd.ParseFlags([]string{"--handshake-timeout=-1s"}))
	var opt server.Opt
	require.NoError(t, unmarshalFlags(cmd, &opt))
	require.ErrorContains(t, opt.Validate(), "handshake-timeout")
}
