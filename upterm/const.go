package upterm

var Version string = "0.8.2"

const (
	// host
	HostSSHClientVersion  = "SSH-2.0-upterm-host-client"
	HostSSHServerVersion  = "SSH-2.0-upterm-host-server"
	HostAdminSocketEnvVar = "UPTERM_ADMIN_SOCKET"

	// client
	ClientSSHClientVersion = "SSH-2.0-upterm-client-client"

	// server
	ServerSSHServerVersion         = "SSH-2.0-uptermd"
	ServerServerInfoRequestType    = "upterm-server-info@upterm.dev"
	ServerCreateSessionRequestType = "upterm-create-session@upterm.dev"

	// misc
	OpenSSHKeepAliveRequestType = "keepalive@openssh.com"

	SSHCertExtension = "upterm-auth-request"

	EventClientJoined          = "client-joined"
	EventClientLeft            = "client-left"
	EventTerminalWindowChanged = "terminal-window-changed"
	EventTerminalDetached      = "terminal-detached"
)
