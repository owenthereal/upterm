package routing

// Mode defines how session routing information is stored and encoded
type Mode string

const (
	// ModeEmbedded embeds node address in the session identifier (default)
	ModeEmbedded Mode = "embedded"
	// ModeConsul looks up node address from Consul
	ModeConsul Mode = "consul"
	// ModeAuto resolves to ModeConsul when a Consul URL is configured and to
	// ModeEmbedded otherwise. It lets a deployment leave routing unset until
	// runtime, when it may or may not have Consul attached.
	ModeAuto Mode = "auto"
)
