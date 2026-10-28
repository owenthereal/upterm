package server

import "golang.org/x/crypto/ssh"

// listenerKind is which of a node's SSH listeners accepted a connection. A
// connection that presents no certificate this relay minted takes its origin,
// the AuthRequest's ingress fields, from that alone, so a listener claims an
// entry point only where nothing else arrives on it.
type listenerKind int

const (
	// listenerShared, the zero value, is the node's SSH listener when it has no
	// internal one. Direct clients, other nodes' hops and the guests a
	// WebSocket bridge hands over raw, this node's over loopback and a
	// neighbour's, all arrive on it, and a bridged guest looks just like a
	// direct one, so it claims nothing.
	listenerShared listenerKind = iota
	// listenerPublic is the node's SSH listener when an internal one exists to
	// take the hops and the bridged guests, which leaves it direct SSH clients
	// alone.
	listenerPublic
	// listenerInternal is where other relay nodes reach this node's SSH proxy,
	// not its own sshd: their hops, and the guests their WebSocket bridges hand
	// over raw. A raw connection on it is such a guest or an unknown peer, and
	// its entry node isn't carried. Carrying it would take terminating the
	// guest's SSH on the neighbour and hopping it here signed, an extra SSH
	// termination for every such guest.
	listenerInternal
	// listenerBridge is fed only by this node's own WebSocket listener, with
	// the guests it bridges.
	listenerBridge
)

// originOf is where conn, a direct connection that a listener of kind on the
// node at nodeAddr accepted, entered the fleet: its ingress, the node it
// entered by, and its own SSH session ID there. Only the public listener and
// this node's bridge establish an entry point; anywhere else the relay claims
// nothing, and names no node. The session ID is conn's either way, this node
// being the one that terminates the guest's SSH.
func originOf(kind listenerKind, conn ssh.ConnMetadata, nodeAddr string) (Ingress, string, []byte) {
	switch kind {
	case listenerPublic:
		return Ingress_INGRESS_SSH, nodeAddr, conn.SessionID()
	case listenerBridge:
		return Ingress_INGRESS_WEBSOCKET, nodeAddr, conn.SessionID()
	}
	// The shared listener, and a raw connection on the internal one.
	return Ingress_INGRESS_UNSPECIFIED, "", conn.SessionID()
}
