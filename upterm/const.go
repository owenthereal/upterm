package upterm

const (
	// host
	HostSSHClientVersion  = "SSH-2.0-upterm-host-client"
	HostSSHServerVersion  = "SSH-2.0-upterm-host-server"
	HostAdminSocketEnvVar = "UPTERM_ADMIN_SOCKET"

	// client
	ClientSSHClientVersion = "SSH-2.0-upterm-client-client"

	// server
	ServerSSHServerVersion         = "SSH-2.0-uptermd"
	ServerPingRequestType          = "upterm-ping@upterm.dev" // TODO: deprecate
	ServerServerInfoRequestType    = "upterm-server-info@upterm.dev"
	ServerCreateSessionRequestType = "upterm-create-session@upterm.dev"

	// misc
	OpenSSHKeepAliveRequestType = "keepalive@openssh.com"
)
