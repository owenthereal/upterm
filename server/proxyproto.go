package server

import (
	"fmt"
	"net"

	"github.com/pires/go-proxyproto"
)

func listenSSH(network, addr string) (net.Listener, error) {
	if network == "" {
		network = "tcp"
	}
	return net.Listen(network, addr)
}

// RequireProxyV2 wraps an SSH listener to require a PROXY protocol v2 header
// with command PROXY and transport TCPv4 or TCPv6. Embedders can use
// this wrapper to enforce the same policy as ssh-proxy-protocol-required.
// Headers are validated on the connection's first Read or Write, before any
// SSH bytes are sent; Accept does not wait for a header.
func RequireProxyV2(ln net.Listener) net.Listener {
	return &proxyproto.Listener{
		Listener:   ln,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.REQUIRE, nil },
		ValidateHeader: func(header *proxyproto.Header) error {
			if header.Version != 2 {
				return fmt.Errorf("PROXY protocol version 2 is required")
			}
			if header.Command != proxyproto.PROXY {
				return fmt.Errorf("PROXY protocol command PROXY is required")
			}
			if header.TransportProtocol != proxyproto.TCPv4 && header.TransportProtocol != proxyproto.TCPv6 {
				return fmt.Errorf("PROXY protocol transport must be TCPv4 or TCPv6")
			}
			return nil
		},
	}
}
