package routing

// Mode defines how session routing information is stored and encoded
type Mode string

const (
	// ModeEmbedded embeds node address in the session identifier (default)
	ModeEmbedded Mode = "embedded"
	// ModeConsul looks up node address from Consul
	ModeConsul Mode = "consul"
)
