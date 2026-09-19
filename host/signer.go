package host

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/term"
)

const (
	errCannotDecodeEncryptedPrivateKeys = "cannot decode encrypted private keys"
)

type errDescryptingPrivateKey struct {
	file string
}

func (e *errDescryptingPrivateKey) Error() string {
	return fmt.Sprintf("error decrypting private key %s", e.file)
}

// Signers returns the identities upterm host offers to the server, and a
// cleanup that releases the agent connection they may sign through.
//
// With identitiesOnly, privateKeys is the whole set and must be non-empty:
// each entry must resolve to a signer, a public key file selects the agent
// key it names, and the agent is otherwise used only to sign a key it
// already holds that the file itself cannot supply — encrypted, or
// otherwise unparseable with a `.pub` sibling. Without it, the agent's
// keys are preferred when it has any, then the files that load, then a
// generated key.
func Signers(privateKeys []string, identitiesOnly bool) ([]ssh.Signer, func(), error) {
	if identitiesOnly {
		return identitySigners(privateKeys, os.Getenv("SSH_AUTH_SOCK"), promptForPassphrase)
	}

	var (
		signers []ssh.Signer
		cleanup func()
		err     error
	)

	signers, cleanup, err = signersFromSSHAgent(os.Getenv("SSH_AUTH_SOCK"))
	if len(signers) == 0 || err != nil {
		signers, err = SignersFromFiles(privateKeys)
	}

	if len(signers) == 0 || err != nil {
		signers, err = utils.CreateSigners(nil)
	}

	return signers, cleanup, err
}

// identitySigners resolves an explicit identity list, OpenSSH's
// IdentitiesOnly: every entry must produce a signer, and nothing the agent
// holds is offered unless an entry names it.
func identitySigners(files []string, agentSocket string, prompt func(file string) ([]byte, error)) ([]ssh.Signer, func(), error) {
	if len(files) == 0 {
		return nil, nil, errors.New("private-key was supplied but names no files")
	}

	ag := &lazyAgent{socket: agentSocket}
	var signers []ssh.Signer
	for _, file := range files {
		s, err := identitySigner(file, ag, prompt)
		if err != nil {
			ag.close()
			return nil, nil, err
		}
		signers = append(signers, s)
	}
	return signers, ag.close, nil
}

// identitySigner resolves one entry of an explicit identity list.
func identitySigner(file string, ag *lazyAgent, prompt func(file string) ([]byte, error)) (ssh.Signer, error) {
	pb, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key %s: %w", file, err)
	}

	// A public key selects the agent key it names, as an IdentityFile that
	// names a .pub does in OpenSSH. It is the only way to pick one identity
	// that exists nowhere but in an agent.
	if pub, _, _, rest, err := ssh.ParseAuthorizedKey(pb); err == nil {
		// One entry names one identity. Pointing it at a file of many —
		// ~/.ssh/authorized_keys, say — would otherwise silently mean "the
		// first key in it", which is a guess this has no business making.
		// The test is whether another key *parses* out of what follows, not
		// whether anything follows at all: a real .pub ends in a newline and
		// may carry blank or `#` comment lines, and ParseAuthorizedKey skips
		// exactly those before it looks for a key, so they leave a non-empty
		// rest that yields no second key.
		if _, _, _, _, err := ssh.ParseAuthorizedKey(rest); err == nil {
			return nil, fmt.Errorf("%s names more than one key; name a file with a single key", file)
		}
		s, err := ag.signerFor(pub)
		if err != nil {
			return nil, fmt.Errorf("%s: %w%s", file, err, publicKeySelectorHint(file))
		}
		return s, nil
	}

	key, err := ssh.ParseRawPrivateKey(pb)
	if err == nil {
		// Directly usable, so the agent is not contacted even if it holds
		// the same key: no round trip, and no confirmation prompt for a key
		// that is right here.
		return ssh.NewSignerFromKey(key)
	}
	var missing *ssh.PassphraseMissingError
	encrypted := errors.As(err, &missing) || strings.Contains(err.Error(), errCannotDecodeEncryptedPrivateKeys)
	if !encrypted {
		// Not encrypted, but still not a signer: x/crypto's OpenSSH key-type
		// switch has no case for sk-ssh-ed25519@openssh.com or
		// sk-ecdsa-sha2-nistp256@openssh.com, so a FIDO/security-key private
		// file — a key-handle stub, not a private key — lands here with
		// "ssh: unhandled key type". That file names an identity it cannot
		// itself sign with; if the agent holds it, resolve through the agent
		// by its public half. The .pub sibling is tried first, matching
		// OpenSSH's own fallback order; failing that, the openssh-key-v1
		// container carries its public key in the clear ahead of the private
		// section, so it can be recovered. See embeddedPublicKey for details.
		pub := publicKeyBeside(file)
		if pub == nil {
			pub = embeddedPublicKey(pb)
		}
		if pub != nil {
			s, agentErr := ag.signerFor(pub)
			if agentErr == nil {
				return s, nil
			}
			return nil, fmt.Errorf("cannot parse private key %s: %w (and the agent could not supply it either: %w)", file, err, agentErr)
		}
		return nil, fmt.Errorf("cannot parse private key %s: %w", file, err)
	}

	// Encrypted. If the agent holds it, sign there rather than asking for
	// the passphrase, which is what keeps an unlocked agent key silent.
	// OpenSSH-format files carry their public half and x/crypto surfaces
	// it; a legacy PEM file does not, so its .pub sibling stands in, as it
	// does for OpenSSH. Neither being available just means the prompt.
	var pub ssh.PublicKey
	if missing != nil {
		pub = missing.PublicKey
	}
	if pub == nil {
		pub = publicKeyBeside(file)
	}
	if pub != nil {
		if s, err := ag.signerFor(pub); err == nil {
			return s, nil
		}
	}

	key, err = decryptPrivateKey(file, pb, prompt)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

// publicKeySelectorHint returns the parenthetical to append when a .pub
// selector could not be resolved, or "" when there is nothing worth
// suggesting. Naming the public half — `-i ~/.ssh/id_ed25519.pub` — is an
// easy slip, and since an unresolvable entry became fatal it stops the host
// with a message that on its own suggests nothing: a .pub selects a key the
// *agent* holds, so both ways that lookup fails, no agent at all and an agent
// that is simply not holding it, read as a puzzle when the private key was
// sitting right beside it all along. The suggestion is made only when the
// sibling with ".pub" stripped exists, so it always names a file that is
// really there; a lone .pub, which is the deliberate use of a selector, gets
// the bare error.
func publicKeySelectorHint(file string) string {
	private, ok := strings.CutSuffix(file, ".pub")
	if !ok {
		return ""
	}
	if _, err := os.Stat(private); err != nil {
		return ""
	}
	return fmt.Sprintf(" (a .pub file selects an agent key; name %s to use the private key itself)", private)
}

// publicKeyBeside returns the key in <file>.pub, or nil when there is none
// that parses. Absence is ordinary — the passphrase prompt is the fallback —
// so it is not an error.
func publicKeyBeside(file string) ssh.PublicKey {
	b, err := os.ReadFile(file + ".pub")
	if err != nil {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil
	}
	return pub
}

// openSSHPrivateKeyMagic is the fixed prefix of an openssh-key-v1 container,
// checked the same way golang.org/x/crypto/ssh's parseOpenSSHPrivateKey does
// before it Unmarshals the rest.
const openSSHPrivateKeyMagic = "openssh-key-v1\x00"

// openSSHPrivateKeyContainer mirrors the wire layout x/crypto's unexported
// openSSHEncryptedPrivateKey decodes an openssh-key-v1 file into
// (golang.org/x/crypto/ssh/keys.go, v0.57.0): CipherName, KdfName and
// KdfOpts describe how PrivKeyBlock is (or is not) encrypted, but PubKey
// sits ahead of all of that, in the clear, whether or not the file is
// encrypted. x/crypto's struct is unexported; ssh.Unmarshal only needs the
// field order and tags to match, which this does.
type openSSHPrivateKeyContainer struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	Rest         []byte `ssh:"rest"`
}

// embeddedPublicKey recovers the public key an openssh-key-v1 container
// carries in the clear, ahead of its (possibly encrypted) private section,
// for a file whose inner key type x/crypto's parseOpenSSHPrivateKey does not
// recognise at all — a FIDO/security-key stub, for one. x/crypto surfaces
// that same embedded key on its own for an *encrypted* file, via
// PassphraseMissingError.PublicKey; it has no such path for an unencrypted
// file of an unrecognised type, which reaches its keytype switch's default
// case and returns a bare "ssh: unhandled key type", the public key it had
// already parsed simply discarded. This helper repeats that bit of parsing.
// It returns nil, not an error, when pb is not such a container, names more
// than one key, or its public key blob does not itself parse — absence here
// is exactly as ordinary as a missing .pub sibling.
func embeddedPublicKey(pb []byte) ssh.PublicKey {
	block, _ := pem.Decode(pb)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil
	}
	if !bytes.HasPrefix(block.Bytes, []byte(openSSHPrivateKeyMagic)) {
		return nil
	}

	var w openSSHPrivateKeyContainer
	if err := ssh.Unmarshal(block.Bytes[len(openSSHPrivateKeyMagic):], &w); err != nil {
		return nil
	}
	if w.NumKeys != 1 {
		// x/crypto itself only supports single-key files, and so does
		// OpenSSH; anything else is not a shape worth guessing at.
		return nil
	}

	pub, err := ssh.ParsePublicKey(w.PubKey)
	if err != nil {
		return nil
	}
	return pub
}

// lazyAgent dials the agent the first time an entry needs it, so a list of
// unencrypted files never opens the socket, and shares one connection across
// the entries that do.
type lazyAgent struct {
	socket string
	once   sync.Once
	conn   net.Conn
	client agent.ExtendedAgent
	err    error
}

func (a *lazyAgent) dial() {
	if a.socket == "" {
		a.err = errors.New("SSH agent is not running")
		return
	}
	conn, err := net.Dial("unix", a.socket)
	if err != nil {
		a.err = err
		return
	}
	a.conn = conn
	a.client = agent.NewClient(conn)
}

// signerFor returns the agent's signer for pub, or an error naming the key
// when no agent holds it. An exact match wins. Failing that, a raw key also
// selects a certificate entry carrying that key, as OpenSSH's IdentityFile
// does, while a selector that is itself a certificate matches only that
// certificate. The agent's listing does return every key it holds; only the
// one asked for is ever returned to a caller.
func (a *lazyAgent) signerFor(pub ssh.PublicKey) (ssh.Signer, error) {
	a.once.Do(a.dial)
	fingerprint := utils.FingerprintSHA256(pub)
	if a.err != nil {
		return nil, fmt.Errorf("no SSH agent to look up %s in: %w", fingerprint, a.err)
	}
	signers, err := a.client.Signers()
	if err != nil {
		return nil, fmt.Errorf("listing SSH agent keys: %w", err)
	}
	want := pub.Marshal()
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), want) {
			return s, nil
		}
	}
	if _, isCert := pub.(*ssh.Certificate); !isCert {
		for _, s := range signers {
			// An agent signer's PublicKey is an *agent.Key — a blob with a
			// type name, never a parsed certificate — so a type assertion on
			// it would never match. Parse the blob to see what it is; the
			// agent-backed signer itself is what is returned.
			parsed, err := ssh.ParsePublicKey(s.PublicKey().Marshal())
			if err != nil {
				continue
			}
			if cert, ok := parsed.(*ssh.Certificate); ok && bytes.Equal(cert.Key.Marshal(), want) {
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("the SSH agent does not hold %s", fingerprint)
}

func (a *lazyAgent) close() {
	if a.conn != nil {
		_ = a.conn.Close()
	}
}

func SignersFromFiles(privateKeys []string) ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, file := range privateKeys {
		s, err := signerFromFile(file, promptForPassphrase)
		if err == nil {
			signers = append(signers, s)
		}
	}

	return signers, nil
}

func signersFromSSHAgent(socket string) ([]ssh.Signer, func(), error) {
	cleanup := func() {}
	if socket == "" {
		return nil, cleanup, fmt.Errorf("SSH Agent is not running")
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { _ = conn.Close() }

	client := agent.NewClient(conn)
	signers, err := client.Signers()

	return signers, cleanup, err
}

func signerFromFile(file string, promptForPassphrase func(file string) ([]byte, error)) (ssh.Signer, error) {
	key, err := readPrivateKeyFromFile(file, promptForPassphrase)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(key)
}

func readPrivateKeyFromFile(file string, promptForPassphrase func(file string) ([]byte, error)) (interface{}, error) {
	pb, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParseRawPrivateKey(pb)
	if err == nil {
		return key, err
	}

	var e *ssh.PassphraseMissingError
	if !errors.As(err, &e) && !strings.Contains(err.Error(), errCannotDecodeEncryptedPrivateKeys) {
		return nil, err
	}

	return decryptPrivateKey(file, pb, promptForPassphrase)
}

// decryptPrivateKey asks prompt for the passphrase, three times as ssh does.
func decryptPrivateKey(file string, pb []byte, prompt func(file string) ([]byte, error)) (interface{}, error) {
	for i := 0; i < 3; i++ {
		pass, err := prompt(file)
		if err != nil {
			return nil, err
		}

		key, err := ssh.ParseRawPrivateKeyWithPassphrase(pb, bytes.TrimSpace(pass))
		if err == nil {
			return key, nil
		}

		if !errors.Is(err, x509.IncorrectPasswordError) {
			return nil, err
		}
	}

	return nil, &errDescryptingPrivateKey{file}
}

func promptForPassphrase(file string) ([]byte, error) {
	defer fmt.Println("") // clear return

	fmt.Printf("Enter passphrase for key '%s': ", file)

	return term.ReadPassword(int(syscall.Stdin))
}

// NewHostKey generates the key the embedded sshd presents on both its doors
// and the key the relay is told to expect from this host. It is a session's
// key, not the operator's: fresh per run, never read from disk, never offered
// to the relay as an identity.
func NewHostKey() (ssh.Signer, error) {
	signers, err := utils.CreateSigners(nil)
	if err != nil {
		return nil, err
	}
	return signers[0], nil
}
