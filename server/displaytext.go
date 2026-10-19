package server

import (
	"fmt"

	"github.com/owenthereal/upterm/upterm"
)

// displayRejection is the sentence a person using plain ssh reads in place of
// wire, one of the relay's texts for rejecting a guest's session channel,
// naming the session sessionID as a banner does; or ("", false) for any other
// message.
func displayRejection(wire, sessionID string) (string, bool) {
	id := bannerSessionID(sessionID)
	switch wire {
	case upterm.UpstreamNoHost:
		return fmt.Sprintf("upterm: no host is connected for session %s right now; it may have ended, or the ID may be wrong.", id), true
	case upterm.UpstreamLookupFailed:
		return "upterm: the relay can't look up sessions right now; try again shortly.", true
	case upterm.UpstreamKeyRefused:
		return fmt.Sprintf("upterm: session %s refused your key; if another key is authorized, pass it with ssh -i, or ask the host to add yours.", id), true
	case upterm.UpstreamAuthFailed:
		return fmt.Sprintf("upterm: session %s refused your key, or the relay has no such session.", id), true
	case upterm.UpstreamUnavailable:
		return fmt.Sprintf("upterm: the relay can't reach the host of session %s right now; try again shortly.", id), true
	case upterm.UpstreamHostKeyMismatch:
		return fmt.Sprintf("upterm: the relay couldn't verify the host of session %s.", id), true
	default:
		return "", false
	}
}

// rejectionRewriteFor is how this node words the channel rejections it sends a
// client announcing clientVersion, whose user names sessionID; hop reports that
// the client authenticated as another relay node. A plain ssh client is shown
// displayRejection's sentence for each wire text. upterm join and a relay node
// match the wire texts, and a host reads them, so each of those gets nil, which
// leaves every message as it is.
func rejectionRewriteFor(clientVersion string, hop bool, sessionID string) rejectionRewrite {
	if hop || clientVersion == upterm.JoinSSHClientVersion || clientVersion == upterm.HostSSHClientVersion {
		return nil
	}
	return func(msg string) string {
		if text, ok := displayRejection(msg, sessionID); ok {
			return text
		}
		return msg
	}
}
