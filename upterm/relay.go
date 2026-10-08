package upterm

// The relay's guest-facing texts. upterm join matches them, so each is a wire
// contract: change one only together with join's classifier, and the golden
// test in relay_test.go.
const (
	// BannerNoHostFormat is sent, with the session ID, when no host is
	// connected for the session. join matches it by BannerNoHostPrefix.
	BannerNoHostFormat = "upterm: no host is connected for session %s right now. " +
		"If it is reconnecting, this same ssh command will work again once it's back. " +
		"Try again in a few seconds.\n"
	BannerNoHostPrefix = "upterm: no host is connected for session "
	// BannerLookupFailed is sent when the relay's session store failed.
	BannerLookupFailed = "upterm: the relay can't look up sessions right now. Try again shortly.\n"

	// The messages of a rejected session channel, when the relay completed a
	// guest's handshake and then failed upstream (server/sshstock.go,
	// upstreamFailureReason).
	UpstreamUnavailable     = "upstream unavailable"
	UpstreamAuthFailed      = "ssh: unable to authenticate with the upstream"
	UpstreamHostKeyMismatch = "ssh: host key mismatch"
	// The next hop's verdict, kept: the relay node that receives the session
	// node's banner turns it into one of these. A node that predates these
	// verdicts reports UpstreamAuthFailed instead, which therefore stays
	// ambiguous: "refused, or no session". Nodes nearer the guest forward a
	// converted verdict unchanged, older ones included.
	UpstreamNoHost       = "upstream has no session"
	UpstreamLookupFailed = "upstream can't look up sessions"
	UpstreamKeyRefused   = "upstream refused the key"

	// HopBannerKeyRefused is what the node holding a session sends another
	// relay node, never a guest, when it refuses the key that node presents.
	// It is read only by relays; no person sees it.
	HopBannerKeyRefused = "upterm-hop: key refused\n"

	// JoinSSHClientVersion is upterm join's SSH version string. The relay
	// treats anything but the exact HostSSHClientVersion as a guest.
	JoinSSHClientVersion = "SSH-2.0-upterm-join"
)
