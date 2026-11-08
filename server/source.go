// Package server is uptermd, the relay that hosts register sessions with and
// guests join them through.
//
// # Extension API
//
// A program that embeds uptermd adds to the relay through these
// declarations:
//
//   - [Extensions], what the program adds, and its Sources field;
//   - [SourceFilter], which denies sources beyond DenySources;
//   - [GuestOrigin], where a connection entered the fleet;
//   - [Opt.NodeID], [Opt.DenySources], [Opt.BootID] and [Opt.Extensions];
//   - [Server.NodeID], [Server.BootID], [Server.DenySources] and
//     [Server.Extensions].
//
// This API may change in any minor release, and each change is listed in the
// release notes.
//
// # Refusing sources
//
// A Server refuses connections from the sources in its DenySources, and from
// those its Extensions.Sources filter denies. A source is checked:
//
//   - on the SSH listener, by the connection's peer, after any PROXY header
//     has been read and before the SSH banner is sent: the connection is
//     closed and nothing is written;
//   - at the WebSocket upgrade, by the client's address, which is answered
//     403 with an empty body;
//   - at host registration, by the source the host's certificate records,
//     which is refused with an empty reply and stores no route, unless this
//     node's WebSocket bridge carried the host;
//   - on a node hop, by the source the hop's certificate records, which is
//     refused at authentication.
//
// The internal listener and this node's WebSocket bridge never check their
// own peer's address: that peer is another node, or this one. A guest that a
// WebSocket listener hands over on either, and a host this node's bridge
// carried, was checked by its client's address at the upgrade instead.
//
// A source is only as true as the address the relay sees, which has three
// consequences. Behind a front that sends no PROXY header, such as an HTTP
// proxy in front of the WebSocket listener, the source is the front, so
// denying it refuses everyone behind it. On an SSH listener that other
// nodes also hop to, there being no internal listener, the source can be a
// node, so a list that names a fleet address refuses that node's hops. And
// without an internal listener, this node's WebSocket listener hands its
// clients over on the SSH listener itself, from this machine's own address,
// so a list that names that address, such as loopback, refuses every
// WebSocket client.
package server

import (
	"errors"
	"net"
	"net/netip"

	"github.com/owenthereal/upterm/internal/sourcecheck"
)

// SourceFilter denies sources beyond a Server's DenySources. It is asked on
// every connection, so Denied must answer from what it already holds: it must
// not block or do I/O. addr is never an IPv4-mapped IPv6 address; those are
// unmapped first. A link-local peer's address keeps its zone.
type SourceFilter interface {
	Denied(addr netip.Addr) bool
}

// errSourceDenied refuses a connection whose source is denied.
var errSourceDenied = errors.New("source is denied")

// parseDenySources parses the --deny-source values, each an IP address or a
// CIDR, into the prefixes they deny.
func parseDenySources(values []string) ([]netip.Prefix, error) {
	return sourcecheck.DenySources(values)
}

// sourceDenied reports whether the source at addr, a host:port as a
// connection reports it, is denied by builtin or by f. An address that
// doesn't parse is not denied: there is nothing to match it against.
func sourceDenied(builtin []netip.Prefix, f SourceFilter, addr string) bool {
	if len(builtin) == 0 && f == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ipDenied(builtin, f, ip.Unmap())
}

// ipDenied is sourceDenied for an address already parsed and unmapped.
func ipDenied(builtin []netip.Prefix, f SourceFilter, ip netip.Addr) bool {
	// A prefix never contains an address with a zone, which a link-local
	// peer's carries, so it is matched without one.
	unzoned := ip.WithZone("")
	for _, prefix := range builtin {
		if prefix.Contains(unzoned) {
			return true
		}
	}
	return f != nil && f.Denied(ip)
}

// sourceDeny is what a component refuses sources by: the Server's DenySources
// and its extensions' filter.
type sourceDeny struct {
	prefixes []netip.Prefix
	filter   SourceFilter
}

// any reports whether anything can be denied at all, so that a relay that
// denies nothing doesn't look at an address it has no use for.
func (d sourceDeny) any() bool { return len(d.prefixes) > 0 || d.filter != nil }

func (d sourceDeny) denied(addr string) bool { return sourceDenied(d.prefixes, d.filter, addr) }
