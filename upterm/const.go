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

	// server
	ServerSSHServerVersion         = "SSH-2.0-uptermd"
	ServerServerInfoRequestType    = "upterm-server-info@upterm.dev"
	ServerCreateSessionRequestType = "upterm-create-session@upterm.dev"

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
