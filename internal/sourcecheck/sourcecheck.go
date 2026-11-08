// Package sourcecheck checks the values of uptermd's --node-id and
// --deny-source, for the server and for the command, which checks them before
// an extension sees its configuration. Both report a bad value in the same
// words.
package sourcecheck

import (
	"errors"
	"fmt"
	"net/netip"
)

// Check reports the first of nodeID and denySources that uptermd refuses.
func Check(nodeID string, denySources []string) error {
	if err := NodeID(nodeID); err != nil {
		return err
	}
	_, err := DenySources(denySources)
	return err
}

// NodeID refuses a node ID other than an empty one, or up to 128 letters,
// digits, '.', '_' and '-'. It goes into logs, and to extensions that may pass
// it on, so it is kept to characters that need no quoting anywhere.
func NodeID(id string) error {
	if !validNodeID(id) {
		return fmt.Errorf("--node-id %q: use at most 128 letters, digits, '.', '_' and '-'", id)
	}
	return nil
}

func validNodeID(id string) bool {
	if len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// DenySources parses the --deny-source values, each an IP address or a CIDR,
// into the prefixes they deny. An address denies itself alone.
func DenySources(values []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, value := range values {
		prefix, err := denySource(value)
		if err != nil {
			return nil, fmt.Errorf("--deny-source %q: not an IP address or CIDR", value)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func denySource(value string) (netip.Prefix, error) {
	if addr, err := netip.ParseAddr(value); err == nil {
		// A zone names an interface on this machine, not a source.
		if addr.Zone() != "" {
			return netip.Prefix{}, errors.New("an address with a zone")
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = prefix.Masked()
	// A source is unmapped before it is matched, so a prefix inside the
	// IPv4-mapped range is the IPv4 prefix it maps, or it would never match.
	// A wider IPv6 prefix stays IPv6.
	if addr := prefix.Addr(); addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96), nil
	}
	return prefix, nil
}
