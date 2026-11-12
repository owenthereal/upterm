// Package calls is what the test extension and the tests that drive it share:
// the environment it reads, the protocol its runs register with, and the
// lines it logs. It imports nothing of upterm's command line, so that a test
// binary that reads the log doesn't link it: ftests re-executes its own binary
// as the command it hosts, and that binary must start as a plain one does.
package calls

const (
	// RelayEnv is the host:port the broker places every run on, and KeysEnv
	// the relay keys it lists for it, as authorized_keys lines.
	RelayEnv = "UPTERM_TEST_EXTENSION_RELAY"
	KeysEnv  = "UPTERM_TEST_EXTENSION_KEYS"
	// LogEnv, when set, is a file each Broker call and each Place appends a
	// JSON line to, saying what it was given.
	LogEnv = "UPTERM_TEST_EXTENSION_LOG"
	// PrepareErrorEnv, FactoryErrorEnv and PlaceErrorEnv, when set, are the
	// error Prepare, the broker factory and Place return.
	PrepareErrorEnv = "UPTERM_TEST_EXTENSION_PREPARE_ERROR"
	FactoryErrorEnv = "UPTERM_TEST_EXTENSION_FACTORY_ERROR"
	PlaceErrorEnv   = "UPTERM_TEST_EXTENSION_PLACE_ERROR"
	// RewriteConfigEnv, when set, is what Prepare writes to config.yaml before
	// it returns, so that a test can change the file between the parent's
	// read of it and the session process's start.
	RewriteConfigEnv = "UPTERM_TEST_EXTENSION_REWRITE_CONFIG"
)

// Protocol is the delegated protocol the broker's runs register with, which
// the test authority accepts.
const Protocol = "upterm-test-v1"

// Payload is what Prepare hands the session process.
const Payload = "test-payload"

// UpgradeLine is what the extension's upgrade prints.
const UpgradeLine = "the test extension's upgrade ran"

// FlagValue is a flag's value and its source, as the handoff carries them.
type FlagValue struct {
	Value  string
	Source string
}

// Settings is the part of the handoff's host settings the tests read.
type Settings struct {
	ReadOnly     bool
	ForceCommand string
	Proxy        string
}

// FactoryCall is what a LogEnv line says of a Broker call.
type FactoryCall struct {
	Kind           string               `json:"kind"` // "factory"
	Name           string               `json:"name"`
	Settings       Settings             `json:"settings"`
	Extension      map[string]FlagValue `json:"extension"`
	Flags          map[string]FlagValue `json:"flags"`
	UserRefs       []string             `json:"userRefs"`
	AuthorizedKeys []int                `json:"authorizedKeys"` // each file's key count
	Payload        string               `json:"payload"`
}

// PlaceCall is what a LogEnv line says of a Place.
type PlaceCall struct {
	Kind          string   `json:"kind"` // "place"
	Name          string   `json:"name"`
	NameGenerated bool     `json:"nameGenerated"`
	Command       []string `json:"command"`
	ForceCommand  []string `json:"forceCommand"`
	LoginCommand  []string `json:"loginCommand"`
	Capabilities  []string `json:"capabilities"`
}
