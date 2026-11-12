package command

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

// handoffEnv is the variable a session process is started with, which holds
// a delegated run's handoff, and is empty for an ordinary run. Every spawn
// sets it, so a value this process inherited never reaches a session
// process.
const handoffEnv = "UPTERM_DAEMON_HANDOFF"

// maxHandoffBytes bounds an encoded handoff. One environment string can be
// at most 32,767 characters on Windows and 131,072 bytes on Linux, and a
// handoff over either would fail the spawn rather than be refused here.
const maxHandoffBytes = 30000

// handoffVersion is the encoding's version.
const handoffVersion = 1

// errHandoffUnreadable is a session process's handoff that doesn't decode.
var errHandoffUnreadable = errors.New("the settings this run was started with can't be read; start it again")

// keyFileChangedError is an --authorized-keys file whose bytes aren't the
// ones the run was started with.
type keyFileChangedError struct{ path string }

func (e keyFileChangedError) Error() string {
	return e.path + " changed after this run started; start it again"
}

// handoffTooLargeError is a handoff over maxHandoffBytes, n bytes encoded.
type handoffTooLargeError struct{ n int }

func (e handoffTooLargeError) Error() string {
	return fmt.Sprintf("this run's settings take %d bytes, more than the %d a session process can be handed; shorten its flag values, such as --force-command", e.n, maxHandoffBytes)
}

// daemonHandoffState is the handoff a delegated run's session process was
// started with, decoded, or why it couldn't be: the root's pre-run reads it,
// and upterm host's run reports a failure once it can tell the parent.
type daemonHandoffState struct {
	h   Handoff
	err error
}

// daemonHandoff is this process's handoff, when it is a delegated run's
// session process; nil otherwise. Set by the root's pre-run.
var daemonHandoff *daemonHandoffState

// takeHandoff reads this process's handoff, when it is a session process,
// and unsets the variable, so that nothing it starts inherits it: nil for an
// ordinary run, or any other process.
func takeHandoff() *daemonHandoffState {
	if !isDaemonProcess() {
		return nil
	}
	v := os.Getenv(handoffEnv)
	_ = os.Unsetenv(handoffEnv)
	if v == "" {
		return nil
	}
	h, err := decodeHandoff(v)
	return &daemonHandoffState{h: h, err: err}
}

// The handoff's encoding: unpadded base64url of this JSON.
type (
	handoffWire struct {
		V        int          `json:"v"`
		Name     string       `json:"name"`
		Settings HostSettings `json:"settings"`
		Options  optionsWire  `json:"options"`
		Payload  []byte       `json:"payload"`
	}
	optionsWire struct {
		Name               string               `json:"name"`
		NameGiven          bool                 `json:"nameGiven"`
		Flags              map[string]flagWire  `json:"flags"`
		AuthorizedKeyFiles []authorizedKeysWire `json:"authorizedKeyFiles"`
		UserRefs           []userRefWire        `json:"userRefs"`
		Extension          map[string]flagWire  `json:"extension"`
	}
	flagWire struct {
		Value  string     `json:"value"`
		Source FlagSource `json:"source"`
	}
	authorizedKeysWire struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Count  int    `json:"count"`
	}
	userRefWire struct {
		Flag string `json:"flag"`
		Ref  string `json:"ref"`
	}
)

// encodeHandoff is h as a session process is handed it. Key files travel as
// their path, digest and key count, never their keys, and the proxy, which
// can hold a credential, as "". An encoding over maxHandoffBytes is a
// handoffTooLargeError.
func encodeHandoff(h Handoff) (string, error) {
	w := handoffWire{V: handoffVersion, Name: h.Name, Settings: h.Settings, Payload: h.Payload}
	w.Settings.Proxy = ""
	o := h.Options
	w.Options = optionsWire{Name: o.Name, NameGiven: o.NameGiven, Flags: flagsWire(o.Flags), Extension: flagsWire(o.Extension)}
	if fv, ok := w.Options.Flags["proxy"]; ok {
		fv.Value = ""
		w.Options.Flags["proxy"] = fv
	}
	for _, f := range o.AuthorizedKeys {
		w.Options.AuthorizedKeyFiles = append(w.Options.AuthorizedKeyFiles, authorizedKeysWire{Path: f.Path, SHA256: hex.EncodeToString(f.SHA256[:]), Count: len(f.Keys)})
	}
	for _, r := range o.UserRefs {
		w.Options.UserRefs = append(w.Options.UserRefs, userRefWire{Flag: r.Flag, Ref: r.Ref.Raw})
	}
	b, err := json.Marshal(w)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(b)
	if len(enc) > maxHandoffBytes {
		return "", handoffTooLargeError{n: len(enc)}
	}
	return enc, nil
}

func flagsWire(flags map[string]FlagValue) map[string]flagWire {
	if flags == nil {
		return nil
	}
	out := make(map[string]flagWire, len(flags))
	for name, fv := range flags {
		out[name] = flagWire(fv)
	}
	return out
}

// decodeHandoff is the handoff s encodes, its key files read again: an error
// naming a key file whose bytes aren't the ones the parent read, or
// errHandoffUnreadable for anything else that is wrong with it.
func decodeHandoff(s string) (Handoff, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Handoff{}, errHandoffUnreadable
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w handoffWire
	if err := dec.Decode(&w); err != nil || dec.More() || w.V != handoffVersion {
		return Handoff{}, errHandoffUnreadable
	}
	if sessiondir.ValidateName(w.Name) != nil {
		return Handoff{}, errHandoffUnreadable
	}
	switch forwardingGrant(w.Settings.AllowForwarding) {
	case "", forwardLoopback, forwardAny:
	default:
		return Handoff{}, errHandoffUnreadable
	}
	h := Handoff{Name: w.Name, Settings: w.Settings, Payload: w.Payload}
	o := w.Options
	h.Options = HostOptions{Name: o.Name, NameGiven: o.NameGiven}
	if h.Options.Flags, err = flagsOf(o.Flags); err != nil {
		return Handoff{}, err
	}
	if h.Options.Extension, err = flagsOf(o.Extension); err != nil {
		return Handoff{}, err
	}
	userFlags := make(map[string]bool)
	for _, spec := range userSpecs() {
		userFlags["--"+spec.flag] = true
	}
	for _, r := range o.UserRefs {
		ref, err := host.ParseUserRef(r.Ref)
		if err != nil || !userFlags[r.Flag] {
			return Handoff{}, errHandoffUnreadable
		}
		h.Options.UserRefs = append(h.Options.UserRefs, UserRef{Flag: r.Flag, Ref: ref})
	}
	for _, f := range o.AuthorizedKeyFiles {
		digest, err := hex.DecodeString(f.SHA256)
		if err != nil || len(digest) != sha256.Size || !filepath.IsAbs(f.Path) {
			return Handoff{}, errHandoffUnreadable
		}
		file, err := readAuthorizedKeyFile(f.Path)
		if err != nil || !bytes.Equal(file.SHA256[:], digest) || len(file.Keys) != f.Count {
			return Handoff{}, keyFileChangedError{path: f.Path}
		}
		h.Options.AuthorizedKeys = append(h.Options.AuthorizedKeys, file)
	}
	return h, nil
}

func flagsOf(flags map[string]flagWire) (map[string]FlagValue, error) {
	if flags == nil {
		return nil, nil
	}
	out := make(map[string]FlagValue, len(flags))
	for name, fv := range flags {
		switch fv.Source {
		case SourceDefault, SourceCommandLine, SourceEnv, SourceConfig:
		default:
			return nil, errHandoffUnreadable
		}
		out[name] = FlagValue(fv)
	}
	return out, nil
}

// readAuthorizedKeyFile reads the authorized_keys file at path, as
// --authorized-keys names it: its absolute path, its keys, and the digest of
// the bytes they were read from. A file with no key is an error, as it is
// for host.AuthorizedKeysFromFile.
func readAuthorizedKeyFile(path string) (AuthorizedKeyFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return AuthorizedKeyFile{}, err
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		return AuthorizedKeyFile{}, fmt.Errorf("error reading authorized keys file %s: %w", path, err)
	}
	var keys []ssh.PublicKey
	for rest := content; len(rest) > 0; {
		key, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return AuthorizedKeyFile{}, fmt.Errorf("error parsing authorized keys file %s: %w", path, err)
		}
		keys = append(keys, key)
		rest = next
	}
	if len(keys) == 0 {
		return AuthorizedKeyFile{}, fmt.Errorf("no public keys found in %s", path)
	}
	return AuthorizedKeyFile{Path: abs, Keys: keys, SHA256: sha256.Sum256(content)}, nil
}

// applySettings makes h what this run's host flags hold, in the session
// process of a delegated run, where neither the environment nor the config
// file was read for them: every flag-bound variable upterm host reads, and
// where each flag's value came from, as the parent resolved them.
func applySettings(h Handoff) {
	s := h.Settings
	flagServer = s.Server
	flagKnownHostsFilename = s.KnownHosts
	flagProxy = s.Proxy
	flagPrivateKeys = s.PrivateKeys
	flagSkipHostKeyCheck = s.SkipHostKeyCheck
	flagForceCommand = s.ForceCommand
	flagLoginCommand = s.LoginCommand
	flagAccept = s.Accept
	flagAllowExec = s.AllowExec
	flagNoExec = s.NoExec
	flagHideClientIP = s.HideClientIP
	flagReadOnly = s.ReadOnly
	flagAllowSFTP = s.AllowSFTP
	flagNoSFTP = s.NoSFTP
	flagNoForwarding = s.NoForwarding
	flagAllowForwarding = forwardingGrant(s.AllowForwarding)
	flagAllowLocalTCPForwarding = s.AllowLocalTCPForwarding
	flagFullAccess = s.FullAccess
	flagDetach = s.Detach
	flagPtySize = s.PtySize
	flagTerm = s.Term
	flagHostEscapeChar = s.EscapeChar
	flagJoinTimeout = s.JoinTimeout
	flagAuthorizedKeys = s.AuthorizedKeys

	o := h.Options
	// The name this attempt claims, which the parent normalized.
	flagName = ""
	if o.NameGiven {
		flagName = h.Name
	}
	flagHostOutput = o.Flags["output"].Value

	users := make(map[string][]string)
	for _, r := range o.UserRefs {
		users[r.Flag] = append(users[r.Flag], r.Ref.Raw)
	}
	flagAuthorizedUsers = users["--authorized-user"]
	// The per-service flags' users are the reference after its service.
	unprefixed := func(flag, provider string) []string {
		var out []string
		for _, raw := range users[flag] {
			out = append(out, strings.TrimPrefix(raw, provider+":"))
		}
		return out
	}
	flagCodebergUsers = unprefixed("--codeberg-user", "codeberg")
	flagGitHubUsers = unprefixed("--github-user", "github")
	flagGitLabUsers = unprefixed("--gitlab-user", "gitlab")
	flagSourceHutUsers = unprefixed("--srht-user", "srht")

	suppliedFlags, commandLineFlags = map[string]bool{}, map[string]bool{}
	for _, flags := range []map[string]FlagValue{o.Flags, o.Extension} {
		for name, fv := range flags {
			suppliedFlags[name] = fv.Source != SourceDefault
			commandLineFlags[name] = fv.Source == SourceCommandLine
		}
	}
}

// applyExtensionFlags sets cmd's extension flags to the values d's handoff
// holds for them. One that refuses its value fails the handoff.
func applyExtensionFlags(cmd *cobra.Command, d *daemonHandoffState) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		fv, ok := d.h.Options.Extension[f.Name]
		if !ok || !isExtensionFlag(f) || d.err != nil {
			return
		}
		var err error
		if sv, isSlice := f.Value.(pflag.SliceValue); isSlice {
			var elems []string
			if elems, err = splitCSV(f.Name, strings.TrimSuffix(strings.TrimPrefix(fv.Value, "["), "]")); err == nil {
				err = sv.Replace(elems)
			}
		} else {
			err = f.Value.Set(fv.Value)
		}
		if err != nil {
			d.err = errHandoffUnreadable
		}
	})
}
