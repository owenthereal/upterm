package upterm

const (
	// host
	HostSSHClientVersion  = "SSH-2.0-upterm-host-client"
	HostSSHServerVersion  = "SSH-2.0-upterm-host-server"
	HostAdminSocketEnvVar = "UPTERM_ADMIN_SOCKET"
	HostSessionNameEnvVar = "UPTERM_SESSION_NAME"

	// client
	ClientSSHClientVersion  = "SSH-2.0-upterm-client-client"
	AttachSSHClientVersion  = "SSH-2.0-upterm-attach"
	AttachInteractiveEnvVar = "UPTERM_ATTACH_INTERACTIVE"
	// AttachNoticeEnvVar is a line a client of the host door asks to be shown
	// once its screen is drawn: below the replay, which would scroll a line
	// printed before attaching out of sight.
	AttachNoticeEnvVar = "UPTERM_ATTACH_NOTICE"

	// server
	// GateModeRequestType asks the node a hop reached which registration it
	// holds for a routing ID: GateModeRequest, answered by GateModeReply.
	GateModeRequestType = "gate-mode@upterm.dev"
	// GateAdmitRequestType asserts to a delegated registration's home, over
	// the hop, that its authority admitted the hop's guest: GateAdmission,
	// answered by the same GateAdmission, byte for byte.
	GateAdmitRequestType = "gate-admit@upterm.dev"
	// GateHeldRequestType asks a delegated registration's home, over an
	// admitted hop, whether it still holds the registration: GateHeldRequest,
	// answered by GateHeldReply.
	GateHeldRequestType            = "gate-held@upterm.dev"
	ServerSSHServerVersion         = "SSH-2.0-uptermd"
	ServerServerInfoRequestType    = "upterm-server-info@upterm.dev"
	ServerCreateSessionRequestType = "upterm-create-session@upterm.dev"
	// ServerDelegatedControlRequestType is a host's report on its own
	// delegated registration, host to relay: DelegatedControlRequest,
	// answered by DelegatedControlReply or refused with a DelegatedError.
	ServerDelegatedControlRequestType = "upterm-delegated-control@upterm.dev"
	// HostDelegatedDecisionRequestType is a decision about a host's delegated
	// session, relay to host: DelegatedDecision, answered by
	// DelegatedDecisionAck.
	HostDelegatedDecisionRequestType = "upterm-delegated-decision@upterm.dev"

	// header
	HeaderUptermClientVersion = "Upterm-Client-Version"

	// misc
	OpenSSHKeepAliveRequestType = "keepalive@openssh.com"

	SSHCertExtension = "upterm-auth-request"

	EventClientJoined = "client-joined"
	EventClientLeft   = "client-left"

	// Forwarding presence is visible, but does not qualify as a first guest join.
	EventForwardingClientJoined = "forwarding-client-joined"
)
