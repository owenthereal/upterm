package server

import (
	"testing"

	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/require"
)

func TestOptResolvedRouting(t *testing.T) {
	tests := []struct {
		name      string
		routing   routing.Mode
		consulURL string
		want      routing.Mode
	}{
		{name: "auto with consul url resolves to consul", routing: routing.ModeAuto, consulURL: "https://consul:8500", want: routing.ModeConsul},
		{name: "auto without consul url resolves to embedded", routing: routing.ModeAuto, want: routing.ModeEmbedded},
		{name: "explicit consul passes through", routing: routing.ModeConsul, consulURL: "https://consul:8500", want: routing.ModeConsul},
		{name: "explicit embedded passes through even with a consul url", routing: routing.ModeEmbedded, consulURL: "https://consul:8500", want: routing.ModeEmbedded},
		{name: "empty defaults to embedded", want: routing.ModeEmbedded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opt := Opt{Routing: tt.routing, ConsulURL: tt.consulURL}
			require.Equal(t, tt.want, opt.ResolvedRouting())
		})
	}
}

func TestValidateAcceptsAutoWithoutConsulURL(t *testing.T) {
	opt := Opt{SSHAddr: "[::]:2222", Routing: routing.ModeAuto}

	require.NoError(t, opt.Validate())
}

func TestValidateAcceptsAutoWithConsulURL(t *testing.T) {
	opt := Opt{
		SSHAddr:          "[::]:2222",
		Routing:          routing.ModeAuto,
		ConsulURL:        "https://consul:8500",
		ConsulSessionTTL: "1h",
	}

	require.NoError(t, opt.Validate())
}

func TestValidateRejectsUnknownRoutingMode(t *testing.T) {
	opt := Opt{SSHAddr: "[::]:2222", Routing: routing.Mode("nonsense")}

	err := opt.Validate()

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported routing mode")
}
