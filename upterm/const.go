package upterm

const (
	// host
	HostSSHClientVersion  = "SSH-2.0-upterm-host-client"
	HostSSHServerVersion  = "SSH-2.0-upterm-host-server"
	HostAdminSocketEnvVar = "UPTERM_ADMIN_SOCKET"

	// server
	ServerSSHServerVersion      = "SSH-2.0-uptermd"
	ServerPingRequestType       = "upterm-ping@upterm.dev"
	ServerServerInfoRequestType = "upterm-server-info@upterm.dev"
)
