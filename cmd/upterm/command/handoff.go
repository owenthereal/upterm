package command

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
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
	// exact is the extension's flags' values as exactValues took them in
	// the parent, by name.
	exact map[string]exactValue
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
	return readHandoff(v)
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
		// An extension's slice flag's elements, and its map flag's entries:
		// see exactValue.
		Elems   *[]string         `json:"elems,omitempty"`
		Entries map[string]string `json:"entries,omitempty"`
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

// encodeHandoff is h as a session process is handed it, with exact, the
// values of the extension's flags that their string forms don't say exactly.
// Key files travel as their path, digest and key count, never their keys,
// and the proxy, which can hold a credential, as "". An encoding over
// maxHandoffBytes is a handoffTooLargeError.
func encodeHandoff(h Handoff, exact map[string]exactValue) (string, error) {
	w := handoffWire{V: handoffVersion, Name: h.Name, Settings: h.Settings, Payload: h.Payload}
	w.Settings.Proxy = ""
	o := h.Options
	w.Options = optionsWire{Name: o.Name, NameGiven: o.NameGiven, Flags: flagsWire(o.Flags), Extension: flagsWire(o.Extension)}
	if fv, ok := w.Options.Flags["proxy"]; ok {
		fv.Value = ""
		w.Options.Flags["proxy"] = fv
	}
	for name, x := range exact {
		if fv, ok := w.Options.Extension[name]; ok {
			fv.Elems, fv.Entries = x.elems, x.entries
			w.Options.Extension[name] = fv
		}
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
		out[name] = flagWire{Value: fv.Value, Source: fv.Source}
	}
	return out
}

// decodeHandoff is the handoff s encodes, its key files read again: an error
// naming a key file whose bytes aren't the ones the parent read, or
// errHandoffUnreadable for anything else that is wrong with it.
func decodeHandoff(s string) (Handoff, error) {
	d := readHandoff(s)
	return d.h, d.err
}

// readHandoff is the handoff s encodes, as decodeHandoff reads it, with the
// exact values of the extension's flags.
func readHandoff(s string) *daemonHandoffState {
	h, exact, err := decodeHandoffWire(s)
	if err != nil {
		return &daemonHandoffState{err: err}
	}
	return &daemonHandoffState{h: h, exact: exact}
}

func decodeHandoffWire(s string) (Handoff, map[string]exactValue, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Handoff{}, nil, errHandoffUnreadable
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w handoffWire
	if err := dec.Decode(&w); err != nil || dec.More() || w.V != handoffVersion {
		return Handoff{}, nil, errHandoffUnreadable
	}
	if sessiondir.ValidateName(w.Name) != nil {
		return Handoff{}, nil, errHandoffUnreadable
	}
	switch forwardingGrant(w.Settings.AllowForwarding) {
	case "", forwardLoopback, forwardAny:
	default:
		return Handoff{}, nil, errHandoffUnreadable
	}
	h := Handoff{Name: w.Name, Settings: w.Settings, Payload: w.Payload}
	o := w.Options
	h.Options = HostOptions{Name: o.Name, NameGiven: o.NameGiven}
	if h.Options.Flags, err = flagsOf(o.Flags); err != nil {
		return Handoff{}, nil, err
	}
	if h.Options.Extension, err = flagsOf(o.Extension); err != nil {
		return Handoff{}, nil, err
	}
	userFlags := make(map[string]bool)
	for _, spec := range userSpecs() {
		userFlags["--"+spec.flag] = true
	}
	for _, r := range o.UserRefs {
		ref, err := host.ParseUserRef(r.Ref)
		if err != nil || !userFlags[r.Flag] {
			return Handoff{}, nil, errHandoffUnreadable
		}
		h.Options.UserRefs = append(h.Options.UserRefs, UserRef{Flag: r.Flag, Ref: ref})
	}
	for _, f := range o.AuthorizedKeyFiles {
		digest, err := hex.DecodeString(f.SHA256)
		if err != nil || len(digest) != sha256.Size || !filepath.IsAbs(f.Path) {
			return Handoff{}, nil, errHandoffUnreadable
		}
		file, err := readAuthorizedKeyFile(f.Path)
		if err != nil || !bytes.Equal(file.SHA256[:], digest) || len(file.Keys) != f.Count {
			return Handoff{}, nil, keyFileChangedError{path: f.Path}
		}
		h.Options.AuthorizedKeys = append(h.Options.AuthorizedKeys, file)
	}
	exact := make(map[string]exactValue)
	for name, fv := range o.Extension {
		exact[name] = exactValue{elems: fv.Elems, entries: fv.Entries}
	}
	return h, exact, nil
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
		out[name] = FlagValue{Value: fv.Value, Source: fv.Source}
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
		if err := restoreValue(f.Value, fv.Value, d.exact[f.Name]); err != nil {
			d.err = errHandoffUnreadable
		}
	})
}

// exactValue is an extension flag's value where its string form doesn't say
// it exactly: a slice flag's elements, as sliceElems gives them, or the
// entries of a map flag of pflag's, with an int written in decimal. Neither
// is set for any other flag, whose string form is its value.
type exactValue struct {
	elems   *[]string
	entries map[string]string
}

// exactValues is the exact value of each of c's extension flags that has one.
func exactValues(c *cobra.Command) map[string]exactValue {
	out := make(map[string]exactValue)
	c.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if !isExtensionFlag(f) {
			return
		}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			elems := sliceElems(f.Value, sv)
			out[f.Name] = exactValue{elems: &elems}
		} else if entries, ok := mapEntries(f.Value); ok {
			out[f.Name] = exactValue{entries: entries}
		}
	})
	return out
}

// restoreValue gives v, a flag's value, what the parent's flag of the same
// type held: x's elements or entries, or s, the string form of any other.
// A value that already holds it is left as it is: one at its default, which
// the parent's had too, can have a string form its Set doesn't take.
func restoreValue(v pflag.Value, s string, x exactValue) error {
	if sv, ok := v.(pflag.SliceValue); ok {
		var elems []string
		if x.elems != nil {
			elems = *x.elems
		}
		if have := sliceElems(v, sv); slices.Equal(have, elems) && (have == nil) == (elems == nil) {
			return nil
		}
		return sv.Replace(elems)
	}
	if have, ok := mapEntries(v); ok {
		if maps.Equal(have, x.entries) {
			return nil
		}
		// The first Set of a map flag still at its default replaces it, and
		// each one after adds to it.
		for _, k := range slices.Sorted(maps.Keys(x.entries)) {
			if err := v.Set(mapEntryInput(v.Type(), k, x.entries[k])); err != nil {
				return err
			}
		}
		if have, _ := mapEntries(v); !maps.Equal(have, x.entries) {
			return fmt.Errorf("a map's entries can't be set to %v", x.entries)
		}
		return nil
	}
	if v.String() == s {
		return nil
	}
	return v.Set(s)
}

// mapEntryInput is the entry k=v as Set takes it alone, for a map flag of
// pflag's type typ. Set takes an entry with no other "=" as it is, less the
// quotes at its ends, and reads any other as CSV: that one is written as
// CSV, twice, which is still the one entry.
func mapEntryInput(typ, k, v string) string {
	entry := k + "=" + v
	if typ != "stringToString" || !strings.Contains(v, "=") && !strings.HasPrefix(entry, `"`) && !strings.HasSuffix(entry, `"`) {
		return entry
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{entry, entry})
	w.Flush()
	return strings.TrimSuffix(b.String(), "\n")
}

// sliceElems is the elements of sv, which is v, as its Replace takes them.
// pflag's float slices give theirs to six decimal places, so theirs are read
// from the slice each holds.
func sliceElems(v pflag.Value, sv pflag.SliceValue) []string {
	if v.Type() != "float32Slice" && v.Type() != "float64Slice" {
		return sv.GetSlice()
	}
	held, ok := heldValue(v, reflect.Slice)
	if !ok {
		return sv.GetSlice()
	}
	out := make([]string, held.Len())
	for i := range out {
		f := held.Index(i)
		if f.Kind() != reflect.Float32 && f.Kind() != reflect.Float64 {
			return sv.GetSlice()
		}
		out[i] = strconv.FormatFloat(f.Float(), 'g', -1, f.Type().Bits())
	}
	return out
}

// mapEntries is the entries of v, a value of one of pflag's map types, with
// an int written in decimal; false for any other value. Their string forms
// can't be read back exactly, and they give their entries no other way, so
// they are read from the map each holds.
func mapEntries(v pflag.Value) (map[string]string, bool) {
	switch v.Type() {
	case "stringToString", "stringToInt", "stringToInt64":
	default:
		return nil, false
	}
	held, ok := heldValue(v, reflect.Map)
	if !ok || held.Type().Key().Kind() != reflect.String {
		return nil, false
	}
	out := make(map[string]string, held.Len())
	for it := held.MapRange(); it.Next(); {
		switch val := it.Value(); val.Kind() {
		case reflect.String:
			out[it.Key().String()] = val.String()
		case reflect.Int, reflect.Int64:
			out[it.Key().String()] = strconv.FormatInt(val.Int(), 10)
		default:
			return nil, false
		}
	}
	return out, true
}

// heldValue is what v, a value of one of pflag's types, holds, as each of
// those holds it: through a pointer in its first field. False when v isn't
// so made, or what it holds isn't of kind.
func heldValue(v pflag.Value, kind reflect.Kind) (reflect.Value, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct || rv.Elem().NumField() == 0 {
		return reflect.Value{}, false
	}
	p := rv.Elem().Field(0)
	if p.Kind() != reflect.Pointer || p.IsNil() || p.Elem().Kind() != kind {
		return reflect.Value{}, false
	}
	return p.Elem(), true
}
