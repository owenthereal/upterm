package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/owenthereal/upterm/join"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultAgentTimeout bounds listing the agent's keys when
// GuestIdentityOptions.AgentTimeout is zero.
const defaultAgentTimeout = 5 * time.Second

var errNoPassphrasePrompt = errors.New("it is encrypted, and nothing can ask for its passphrase")

// GuestIdentityOptions configures NewGuestIdentity.
type GuestIdentityOptions struct {
	// IdentitiesOnly says -i was given: Files is the whole set, each entry
	// must resolve, and no other agent key is offered. An empty Files with
	// IdentitiesOnly is an error, as `upterm host -i` makes it ("private-key
	// was supplied but names no files"); it never falls back to the defaults.
	IdentitiesOnly bool
	Files          []string      // with IdentitiesOnly: -i's entries; otherwise the default files that exist
	AgentSocket    string        // SSH_AUTH_SOCK
	AgentTimeout   time.Duration // bound on listing the agent's keys; 0 = 5 s
	// Passphrase asks for an encrypted key file's passphrase, and returns
	// promptly once ctx ends. It is asked only for a file whose key the agent
	// doesn't hold. Nil leaves such a file unloaded.
	Passphrase func(ctx context.Context, file string) ([]byte, error)
	// OnSkip is told about each key file that didn't load, when another key
	// did: "skipping <file>: <error>". OnAgentSkip is told why the agent was
	// skipped, when a key file loaded instead: "skipping the SSH agent:
	// <error>". Both are called before NewGuestIdentity returns; nil is
	// silent.
	OnSkip      func(file string, err error)
	OnAgentSkip func(err error)
}

// GuestIdentity is the keys a guest offers, prepared once before the first
// attempt and offered again on every rejoin. Its Signers and Source are
// join.Identity's.
type GuestIdentity struct {
	socket string
	keys   []guestKey
	source join.KeySource
}

// guestKey is one identity a GuestIdentity offers: a key the agent holds, by
// its public half, or a signer of its own, a key file's or a generated key.
type guestKey struct {
	agentKey ssh.PublicKey
	signer   ssh.Signer
}

func (k guestKey) publicKey() ssh.PublicKey {
	if k.signer != nil {
		return k.signer.PublicKey()
	}
	return k.agentKey
}

// NewGuestIdentity prepares the keys a guest offers. It runs before the first
// attempt, in cooked mode, under ctx: Ctrl-C there is SIGINT, and ends it with
// ctx's error. It works in ssh's order, so that a key the agent holds never
// asks for a passphrase:
//
//  1. each file's public half, read without a passphrase: the file itself
//     when it is a public key, which selects the agent key it names; a .pub
//     beside it; the file's own key when it is unencrypted; or the public
//     half an encrypted openssh-format file carries;
//  2. the agent's keys, listed over a connection of their own that is closed
//     at AgentTimeout or when ctx ends, so that a silent agent never spends
//     the first join's budget. An agent that fails is skipped for the run;
//  3. each file: the agent's key when the agent holds it, which needs no
//     passphrase and lets a FIDO key sign, and otherwise the file's own key,
//     decrypted with Passphrase if it must be.
//
// Without IdentitiesOnly, every agent key comes first, then each file whose
// key the agent doesn't hold, and a file that doesn't load is skipped. With
// it, the entries are offered in order and no other agent key is, and an entry
// that doesn't load is a *join.IdentityError with Load set. A key named twice
// is offered once either way.
//
// A key is generated only without IdentitiesOnly, when there is no agent key
// (no socket, or an agent that holds none) and no file. An agent that failed,
// with no file that loaded, is a *join.IdentityError with List set; files that
// all failed to load, with no agent key, are one with Load set.
func NewGuestIdentity(ctx context.Context, o GuestIdentityOptions) (*GuestIdentity, error) {
	if o.IdentitiesOnly && len(o.Files) == 0 {
		return nil, errNoPrivateKeyFiles
	}

	// Every public half first, before anything can ask for a passphrase.
	entries := make([]guestEntry, len(o.Files))
	for i, file := range o.Files {
		entries[i].file = file
		entries[i].key, entries[i].err = readGuestKeyFile(file)
		if entries[i].err != nil && o.IdentitiesOnly {
			return nil, loadError(entries[i])
		}
	}

	ag := agentListing{socket: o.AgentSocket}
	if o.AgentSocket != "" {
		timeout := o.AgentTimeout
		if timeout <= 0 {
			timeout = defaultAgentTimeout
		}
		ag.keys, ag.err = listAgentKeys(ctx, o.AgentSocket, timeout)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	g := &GuestIdentity{socket: o.AgentSocket}
	seen := make(map[string]bool)
	offer := func(k guestKey) {
		// Naming one key twice is still one identity, as it is for
		// identitySigners and OpenSSH.
		id := string(k.publicKey().Marshal())
		if seen[id] {
			return
		}
		seen[id] = true
		g.keys = append(g.keys, k)
		if k.signer != nil {
			g.source.Files++
		} else {
			g.source.Agent++
		}
	}
	if !o.IdentitiesOnly {
		for _, s := range ag.keys {
			offer(guestKey{agentKey: s.PublicKey()})
		}
	}

	prompt := func(file string) ([]byte, error) {
		if o.Passphrase == nil {
			return nil, errNoPassphrasePrompt
		}
		return o.Passphrase(ctx, file)
	}
	var failed []guestEntry
	for _, e := range entries {
		if e.err == nil {
			var k guestKey
			if k, e.err = ag.resolve(e.key, prompt); e.err == nil {
				offer(k)
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if o.IdentitiesOnly {
			return nil, loadError(e)
		}
		failed = append(failed, e)
	}

	if len(g.keys) == 0 {
		switch {
		case ag.err != nil:
			return nil, &join.IdentityError{List: true, Load: loadLines(failed), Err: ag.err}
		case len(failed) > 0:
			return nil, &join.IdentityError{Load: loadLines(failed)}
		}
		signers, err := utils.CreateSigners(nil)
		if err != nil {
			return nil, err
		}
		g.keys = []guestKey{{signer: signers[0]}}
		g.source.Generated = true
	}

	if ag.err != nil && o.OnAgentSkip != nil {
		o.OnAgentSkip(ag.err)
	}
	if o.OnSkip != nil {
		for _, e := range failed {
			o.OnSkip(e.file, e.err)
		}
	}
	g.source.Explicit = o.IdentitiesOnly
	return g, nil
}

// Signers is join.Identity.Signers: what one attempt offers, in order, and the
// release that closes the attempt's connection to the agent. A key the agent
// holds is offered by its public half, and reaches the agent only to sign,
// over a connection dialled under ctx that the attempt's other agent keys
// share. A key file's signer, and a generated key, are the ones prepared
// before the first attempt. Signers itself never fails: an agent that stopped
// answering, or no longer holds a key, fails that key's signature instead.
func (g *GuestIdentity) Signers(ctx context.Context) ([]ssh.Signer, func(), error) {
	signers := make([]ssh.Signer, 0, len(g.keys))
	var a *attemptAgent
	for _, k := range g.keys {
		if k.signer != nil {
			signers = append(signers, k.signer)
			continue
		}
		if a == nil {
			a = &attemptAgent{ctx: ctx, socket: g.socket, dial: new(net.Dialer).DialContext}
		}
		signers = append(signers, &lazyIdentity{pub: k.agentKey, agent: a})
	}
	if a == nil {
		return signers, func() {}, nil
	}
	return signers, a.close, nil
}

// Source is join.Identity.Source: the identities as Signers offers them.
func (g *GuestIdentity) Source() join.KeySource { return g.source }

// guestEntry is one of GuestIdentityOptions.Files, and why it failed, if it
// did.
type guestEntry struct {
	file string
	key  *guestKeyFile
	err  error
}

func loadError(e guestEntry) error {
	return &join.IdentityError{Load: loadLines([]guestEntry{e})}
}

// loadLines is each failed entry as "file: error".
func loadLines(failed []guestEntry) []string {
	var lines []string
	for _, e := range failed {
		lines = append(lines, e.file+": "+e.err.Error())
	}
	return lines
}

// guestKeyFile is a key file as it reads without a passphrase.
type guestKeyFile struct {
	file      string
	pb        []byte
	pub       ssh.PublicKey // nil: not known until the file is decrypted
	selector  bool          // the file is a public key, which names an agent key
	signer    ssh.Signer    // the file's own key, when it is unencrypted
	encrypted bool
	err       error // why an unencrypted file is no signer
}

// readGuestKeyFile reads file's public half without a passphrase, from the
// first of: the file itself when it is a public key; the .pub beside it; the
// file's own key when it is unencrypted; and the public half an encrypted
// openssh-format file carries in the clear. A file x/crypto can't load at all,
// a FIDO key's stub say, gives the public half its openssh-format container
// carries. An encrypted PEM file with no .pub beside it has no public half
// until it is decrypted. The error is a file that can't be read, or a public
// key file that names more than one key.
func readGuestKeyFile(file string) (*guestKeyFile, error) {
	pb, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if pub, ok, err := publicKeyEntry(pb); ok {
		if err != nil {
			return nil, err
		}
		return &guestKeyFile{file: file, pb: pb, pub: pub, selector: true}, nil
	}

	k := &guestKeyFile{file: file, pb: pb, pub: publicKeyBeside(file)}
	key, err := ssh.ParseRawPrivateKey(pb)
	if err == nil {
		k.signer, k.err = ssh.NewSignerFromKey(key)
		if k.pub == nil && k.signer != nil {
			k.pub = k.signer.PublicKey()
		}
		return k, nil
	}
	if missing, encrypted := passphraseNeeded(err); encrypted {
		k.encrypted = true
		if k.pub == nil && missing != nil {
			k.pub = missing.PublicKey
		}
		return k, nil
	}
	k.err = err
	if k.pub == nil {
		k.pub = embeddedPublicKey(pb)
	}
	return k, nil
}

// agentListing is what listing the agent found: its keys, or why it was
// skipped.
type agentListing struct {
	socket string
	// keys are the listing's signers, for their public keys alone: their
	// connection was closed once the listing was read.
	keys []ssh.Signer
	err  error
}

// resolve is one key file's identity: the agent's key when the agent holds
// it, and otherwise the file's own key, which only an encrypted file asks a
// passphrase for.
func (ag agentListing) resolve(k *guestKeyFile, prompt func(file string) ([]byte, error)) (guestKey, error) {
	if k.pub != nil {
		if s := agentSignerFor(ag.keys, k.pub); s != nil {
			return guestKey{agentKey: s.PublicKey()}, nil
		}
	}
	switch {
	case k.selector:
		return guestKey{}, fmt.Errorf("%w%s", ag.missing(k.pub), publicKeySelectorHint(k.file))
	case k.signer != nil:
		return guestKey{signer: k.signer}, nil
	case k.encrypted:
		key, err := decryptPrivateKey(k.file, k.pb, prompt)
		if err != nil {
			return guestKey{}, err
		}
		s, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return guestKey{}, err
		}
		return guestKey{signer: s}, nil
	case k.pub != nil:
		// A key the file can't sign with, a FIDO key's stub say, whose
		// public half named nothing the agent holds.
		return guestKey{}, fmt.Errorf("%w (and the agent could not supply it either: %w)", k.err, ag.missing(k.pub))
	}
	return guestKey{}, k.err
}

// missing says why the agent couldn't supply pub, as lazyAgent.signerFor
// does.
func (ag agentListing) missing(pub ssh.PublicKey) error {
	fingerprint := utils.FingerprintSHA256(pub)
	switch {
	case ag.socket == "":
		return fmt.Errorf("no SSH agent to look up %s in: SSH agent is not running", fingerprint)
	case ag.err != nil:
		return fmt.Errorf("no SSH agent to look up %s in: %w", fingerprint, ag.err)
	}
	return fmt.Errorf("the SSH agent does not hold %s", fingerprint)
}

// listAgentKeys lists the keys the agent at socket holds, over a connection of
// its own that is closed when the listing has been read, when ctx ends, or at
// timeout, whichever is first. Only ctx's own end is ctx's error; a listing
// that ran out of time says so.
func listAgentKeys(ctx context.Context, socket string, timeout time.Duration) ([]ssh.Signer, error) {
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := new(net.Dialer).DialContext(lctx, "unix", socket)
	if err == nil {
		stop := context.AfterFunc(lctx, func() { _ = conn.Close() })
		var keys []ssh.Signer
		keys, err = agent.NewClient(conn).Signers()
		stop()
		_ = conn.Close()
		if err == nil {
			return keys, nil
		}
	}
	if ctx.Err() == nil && lctx.Err() != nil {
		return nil, fmt.Errorf("no answer within %v", timeout)
	}
	return nil, err
}
