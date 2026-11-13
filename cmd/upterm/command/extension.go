package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/owenthereal/upterm/host"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/ssh"
)

// Extension is what a program that embeds upterm adds to upterm's command
// line: commands of its own, flags on upterm host, and a say in how a run of
// upterm host is hosted. The zero value adds nothing.
type Extension struct {
	// Name names the extension's entry in config.yaml's extensions mapping,
	// which holds its flags' settings: [a-z][a-z0-9-]{0,31}. It is required.
	Name string
	// Commands are commands to add to upterm's own.
	Commands func() []*cobra.Command
	// HostFlags are flags to add to upterm host.
	HostFlags []HostFlag
	// Prepare, if set, is called in the process an operator runs upterm host
	// in, first: after the flags have their values and before a session name
	// is drawn, a user's keys are fetched or the relay's key is looked at. Its
	// error ends the run, and is printed as it is, made safe for a terminal.
	// It decides whether the run is delegated.
	Prepare func(context.Context, HostOptions) (Prepared, error)
	// Broker, for a delegated run only, is called in the session's own
	// process, which upterm starts for it, with what the run was started
	// with. The Broker it returns places the run; see host.Host.Broker. Its
	// error ends the run, and is printed as it is, made safe for a terminal,
	// as is any error the Broker's Place returns.
	Broker func(context.Context, Handoff) (host.Broker, error)
	// Upgrade, if set, is what upterm upgrade runs, in place of replacing
	// this binary with upterm's own release.
	Upgrade func(*cobra.Command) error
}

// HostFlag is a flag an extension adds to upterm host. A delegated run's
// session process is handed every HostFlag's value in its environment,
// which other processes of the same user can read, so a HostFlag must not
// carry a secret. A value of one of pflag's types reaches that process as it
// was; one of any other type reaches it as its Set takes its String().
type HostFlag struct {
	Flag *pflag.Flag
	// PerRun takes the flag's value from the command line only: a value for
	// it in the environment or config.yaml is ignored, with a notice, as
	// upterm's own per-run flags are. Otherwise its value can also come from
	// UPTERM_FLAG, and from the extension's entry in config.yaml.
	PerRun bool
	// Hidden leaves the flag out of help.
	Hidden bool
	// Validate, if set, is how upterm config edit checks a value config.yaml
	// gives the flag, and how WriteConfigValue checks a value it is given.
	Validate func(any) error
}

// Prepared is Prepare's answer. It stays in the process Prepare ran in.
type Prepared struct {
	// Delegated makes the run a delegated one: the session's process calls
	// Extension.Broker, and its Broker places the run. Otherwise the run is an
	// ordinary one, and Broker isn't called. upterm then enforces none of
	// --authorized-keys, --authorized-user and the per-service user flags,
	// and doesn't refuse a run that asked for them and resolved no key; and
	// it ignores --server, --known-hosts, --skip-host-key-check and --proxy.
	// Refusing what the extension can't honour is Prepare's job.
	Delegated bool
	// NormalizeName, if set, is applied to every name the run claims: the
	// name --name gives, and every one upterm draws. Its result must be a
	// valid session name, and its error ends the run and is printed as it
	// is, made safe for a terminal.
	NormalizeName func(string) (string, error)
	// Payload is handed, as it is, to the Broker call in the session's
	// process. It travels in that process's environment, which other
	// processes of the same user can read, so it must hold no secret.
	Payload []byte
}

// Handoff is what a delegated run's session process is started with, and
// what the extension's Broker is given there: the name it claims, the
// settings it is hosted with, the run's options, and Prepare's payload. None
// of it is a credential: the handoff travels in the process's environment.
type Handoff struct {
	Name     string
	Settings HostSettings
	Options  HostOptions
	Payload  []byte
}

// FlagSource is where a flag's value came from.
type FlagSource string

const (
	SourceDefault     FlagSource = "default"
	SourceCommandLine FlagSource = "command-line"
	SourceEnv         FlagSource = "env"
	SourceConfig      FlagSource = "config"
)

// FlagValue is a flag's value, in its string form, and where it came from.
type FlagValue struct {
	Value  string // pflag.Value.String()
	Source FlagSource
}

// AuthorizedKeyFile is an --authorized-keys file: its absolute path, the keys
// it lists, and the SHA-256 of the bytes they were read from.
type AuthorizedKeyFile struct {
	Path   string
	Keys   []ssh.PublicKey
	SHA256 [32]byte
}

// UserRef is a user a flag names: the flag, such as "--authorized-user" or
// "--github-user", and the user, parsed but not looked up.
type UserRef struct {
	Flag string
	Ref  host.UserRef
}

// HostOptions is a run of upterm host as Prepare is given it, and as the
// handoff carries it.
type HostOptions struct {
	// Name is --name's value, and NameGiven says whether the command line
	// gave one. An empty --name gives none: upterm draws the name.
	Name      string
	NameGiven bool
	// Flags is every upterm host flag by its name, except an extension's. The
	// value of proxy is always "".
	Flags map[string]FlagValue
	// AuthorizedKeys are the --authorized-keys files, read.
	AuthorizedKeys []AuthorizedKeyFile
	// UserRefs are the users --authorized-user and the per-service user
	// flags name, in the order upterm reads them. Nothing has looked up
	// their keys.
	UserRefs []UserRef
	// Extension is the extension's HostFlags, by name.
	Extension map[string]FlagValue
}

// HostSettings is every value upterm host's session is built from.
type HostSettings struct {
	Server, KnownHosts, Proxy                 string
	PrivateKeys                               []string
	IdentitiesOnly, SkipHostKeyCheck          bool
	ForceCommand, LoginCommand                string
	Accept, AllowExec, NoExec, HideClientIP   bool
	ReadOnly, AllowSFTP, NoSFTP, NoForwarding bool
	AllowLocalTCPForwarding                   bool
	AllowForwarding                           string // "", "loopback" or "any"
	FullAccess                                bool
	PtySize, Term, EscapeChar                 string
	JoinTimeout                               time.Duration
	Detach                                    bool
	AuthorizedKeys                            string // the --authorized-keys path; its keys are in HostOptions
}

// extensionNameRe is what an extension's Name must be.
var extensionNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// annotationExtension marks a flag as an extension's HostFlag, with the
// extension's name as its value.
const annotationExtension = "upterm/extension"

// RootWith is the upterm command composed with ext, which may be nil. It
// panics if ext has no valid Name, or names a flag or command upterm already
// has.
func RootWith(ext *Extension) *cobra.Command {
	if ext != nil && !extensionNameRe.MatchString(ext.Name) {
		panic(fmt.Sprintf("upterm: extension name %q is not [a-z][a-z0-9-]{0,31}", ext.Name))
	}
	rootCmd := &cobra.Command{
		Use:   "upterm",
		Short: "Instant Terminal Sharing",
		Long: `Upterm shares a terminal session: you host a command, and guests join it
from their own terminals, through a relay, with upterm join or plain ssh.

Flags can also be set with UPTERM_ environment variables and the config
file: see 'upterm config --help'.`,
		Example: `  # Host $SHELL; upterm prints how guests join it:
  upterm host

  # A guest joins with the connect string the host shares:
  upterm join ssh://ID@uptermd.upterm.dev

  # Or with plain ssh:
  ssh ID@uptermd.upterm.dev`,
		// For every command: cobra checks the root's. Exit prints each error
		// once, as one line, and never the usage; cobra would print
		// "Error: ...", often the usage block too, and then main its own copy.
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootPreRun(cmd)
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if logger := uptermctx.Logger(cmd.Context()); logger != nil {
				return logger.Close()
			}

			return nil
		},
	}

	logPath := utils.UptermLogFilePath()
	rootCmd.PersistentFlags().Bool("debug", os.Getenv("DEBUG") != "",
		fmt.Sprintf("Enable debug logging (log file: %s). A non-empty DEBUG turns it on too.", logPath))

	rootCmd.AddCommand(attachCmd())
	rootCmd.AddCommand(configCmd(ext))
	rootCmd.AddCommand(hostCmdWith(ext))
	rootCmd.AddCommand(joinCmd())
	rootCmd.AddCommand(proxyCmd())
	rootCmd.AddCommand(sessionCmd())
	rootCmd.AddCommand(upgradeCmdWith(ext))
	rootCmd.AddCommand(versionCmd())
	if ext != nil && ext.Commands != nil {
		addExtensionCommands(rootCmd, ext.Commands())
	}

	// cobra's usage template, before the root's is changed below.
	usage := rootCmd.UsageTemplate()
	reportUnknownCommands(rootCmd)
	for _, c := range rootCmd.Commands() {
		switch {
		case !c.HasSubCommands():
		// A group: upterm's own, or an extension's that runs nothing itself.
		case c.Run == nil && c.RunE == nil:
			reportUnknownCommands(c)
		// An extension's command that runs as well: its usage keeps the line
		// that says how to run it.
		default:
			c.SetUsageTemplate(usage)
		}
	}
	helpOnlyForKnownCommands(rootCmd)

	// config's help lists the flags that take values only from the command
	// line, which takes the whole tree.
	if config, _, err := rootCmd.Find([]string{"config"}); err == nil {
		config.Long = configLong(perRunHelp(rootCmd))
	}

	// The root and the groups run only to report an unknown command, so
	// their usage shows the commands they hold and no run of their own:
	// cobra's template, its runnable line kept for a command without
	// subcommands. An extension's command that runs and has subcommands
	// keeps cobra's own, set above.
	rootCmd.SetUsageTemplate(strings.Replace(rootCmd.UsageTemplate(),
		"{{if .Runnable}}", "{{if and .Runnable (not .HasSubCommands)}}", 1))

	return rootCmd
}

// MainWith is the whole of a main that composes upterm with ext, which may be
// nil: the signal policy, the command, the exit status. The session process
// upterm host starts is this same program, so it has ext too.
//
// The signal policy comes first and belongs to this process, not only to the
// daemon's Host.Run: the foreground host and attach hold the terminal here,
// and need SIGPIPE protection and the job-control dispositions before any of
// it is touched.
func MainWith(ext *Extension) int {
	installSignalPolicy()
	cmd, err := execute(mainRoot(ext))
	return Exit(cmd, err, os.Stderr)
}

// reservedCommandNames are the commands cobra adds to upterm's.
var reservedCommandNames = []string{"help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd}

// addExtensionCommands adds cmds to root, and panics if one of them has a
// name or an alias that one of root's commands, or cobra's, has.
func addExtensionCommands(root *cobra.Command, cmds []*cobra.Command) {
	taken := make(map[string]bool)
	for _, name := range reservedCommandNames {
		taken[name] = true
	}
	for _, c := range root.Commands() {
		taken[c.Name()] = true
		for _, alias := range c.Aliases {
			taken[alias] = true
		}
	}
	for _, c := range cmds {
		for _, name := range append([]string{c.Name()}, c.Aliases...) {
			if taken[name] {
				panic(fmt.Sprintf("upterm: an extension's command %q is a name upterm already uses", name))
			}
			taken[name] = true
		}
		root.AddCommand(c)
	}
}

// addHostFlags registers ext's HostFlags on host, upterm host, as their
// HostFlag says: per run, hidden, and in each case marked as ext's. It panics
// on a flag with no Flag, or one whose name or shorthand upterm host already
// has.
func addHostFlags(hostCmd *cobra.Command, ext *Extension) {
	if ext == nil {
		return
	}
	fs := hostCmd.PersistentFlags()
	for _, hf := range ext.HostFlags {
		f := hf.Flag
		if f == nil {
			panic("upterm: an extension's host flag has no Flag")
		}
		if fs.Lookup(f.Name) != nil || f.Name == "help" || f.Name == "debug" {
			panic(fmt.Sprintf("upterm: an extension's host flag --%s is a name upterm host already uses", f.Name))
		}
		if f.Shorthand != "" && (fs.ShorthandLookup(f.Shorthand) != nil || f.Shorthand == "h") {
			panic(fmt.Sprintf("upterm: an extension's host flag -%s is a shorthand upterm host already uses", f.Shorthand))
		}
		fs.AddFlag(f)
		_ = fs.SetAnnotation(f.Name, annotationExtension, []string{ext.Name})
		if hf.PerRun {
			perRun(fs, f.Name)
		}
		if hf.Hidden {
			f.Hidden = true
		}
	}
}

// isExtensionFlag reports whether f is an extension's HostFlag.
func isExtensionFlag(f *pflag.Flag) bool { return hasAnnotation(f, annotationExtension) }

// extensionNameIn is the name of the extension whose HostFlags the tree cmd
// is in has, or "" when it has none.
func extensionNameIn(cmd *cobra.Command) string {
	var name string
	visitTreeFlags(cmd, func(f *pflag.Flag) {
		if v := f.Annotations[annotationExtension]; len(v) > 0 {
			name = v[0]
		}
	})
	return name
}

// Logger is the logger of the command whose context ctx is, as upterm's own
// code logs to it; a logger that discards everything when ctx has none.
func Logger(ctx context.Context) *slog.Logger {
	if ctx != nil {
		if l := uptermctx.Logger(ctx); l != nil && l.Logger != nil {
			return l.Logger
		}
	}
	return slog.New(slog.DiscardHandler)
}

// WriteConfigValue sets key, one of ext's HostFlags that isn't per run, to
// value in ext's entry of config.yaml's extensions mapping, creating the
// file, the mapping and the entry as needed.
//
// The rest of the file is kept. A file that holds a mapping keeps its keys,
// their order and their comments, though it is written out anew, indented
// by two spaces. A file that holds no document, only comments, blank lines,
// a document start and a null, keeps every line but the null's, which keeps
// its comment, and the entry is written after them. A file is written through
// a link to it, and replaced whole: by a file of mode 0600 written beside it
// and renamed into its place. A file of more than one YAML document is
// refused, and so is one where the extensions mapping, the entry or the value
// being replaced has a YAML anchor or is an alias.
//
// Before anything is written, value is set as the config file would set it
// on a copy of the flag, as a run reads it back from the file, for a flag of
// pflag's own types or one whose value isn't a struct, and the HostFlag's
// Validate, if any, checks value as given. A value that would be written as
// null, such as nil, is refused: no run takes it.
//
// It takes no lock. Of two calls at once, each can read the file before the
// other replaces it, and the last to replace it wins: the other's value is
// lost. And the lines it writes end in \n, so a file that holds a mapping
// and whose lines end in \r\n is written back with \n.
func WriteConfigValue(ext *Extension, key string, value any) error {
	if ext == nil || !extensionNameRe.MatchString(ext.Name) {
		return errors.New("an extension needs a valid name to write its settings")
	}
	var flag *HostFlag
	for i, hf := range ext.HostFlags {
		if hf.Flag != nil && hf.Flag.Name == key && !hf.PerRun {
			flag = &ext.HostFlags[i]
		}
	}
	if flag == nil {
		return fmt.Errorf("%s is not a setting of extension %s", key, ext.Name)
	}
	var v yaml.Node
	if err := v.Encode(value); err != nil {
		return fmt.Errorf("can't write %s's value: %w", key, err)
	}
	if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
		return fmt.Errorf("%s: config key has no value", extensionKey(ext.Name, key))
	}
	// Set as the config file would set it, on a copy of the flag, so that a
	// value commands would refuse as the flag's is not written: as a run
	// reads it back from the file, which isn't always the value as given. A
	// flag of a type the copy can't be made of, or whose copy panics, is
	// checked by Validate alone.
	read, err := readBack(ext.Name, key, &v)
	if err != nil {
		return err
	}
	if err := tryValue(flag.Flag.Value, key, read); err != nil {
		return err
	}
	if flag.Validate != nil {
		if err := flag.Validate(value); err != nil {
			return err
		}
	}

	// A config.yaml that is a link is written where it leads, and stays a
	// link.
	path := followLinks(utils.UptermConfigFilePath())
	content, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(content))
	if err := dec.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w; %s", path, err, fixConfig)
	}
	// Only the first document could be written back: the rest would be lost.
	switch err := dec.Decode(new(yaml.Node)); {
	case errors.Is(err, io.EOF):
	case err != nil:
		return fmt.Errorf("%s: %w; %s", path, err, fixConfig)
	default:
		return fmt.Errorf("%s: the file holds more than one YAML document; %s", path, fixConfig)
	}
	// A file that holds no document to edit, only comments and at most a
	// document start and a null, is kept as it is, less the null, and the
	// new document written after it.
	var kept []byte
	if lines, ok := emptyDocument(content); doc.Kind == 0 || ok {
		kept = lines
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	top := doc.Content[0]
	if top.Kind == yaml.ScalarNode && top.Tag == "!!null" {
		*top = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: top.HeadComment, LineComment: top.LineComment, FootComment: top.FootComment}
	}
	if top.Kind != yaml.MappingNode {
		return fmt.Errorf("%s: the file isn't a mapping of keys to values; %s", path, fixConfig)
	}
	if err := anchorOnTheWay(top, extensionsKey, ext.Name, key); err != nil {
		return fmt.Errorf("%s: %w; %s", path, err, fixConfig)
	}
	extensions, err := mappingEntry(top, extensionsKey)
	if err != nil {
		return fmt.Errorf("%s: %w; %s", path, errExtensionsShape, fixConfig)
	}
	entry, err := mappingEntry(extensions, ext.Name)
	if err != nil {
		return fmt.Errorf("%s: %w; %s", path, errExtensionsShape, fixConfig)
	}
	setMappingValue(entry, key, &v)

	out := bytes.NewBuffer(kept)
	enc := yaml.NewEncoder(out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return replaceFile(path, out.Bytes())
}

// readBack is v, written as key's value in the extension extName's entry, as
// a run reads it back from the config file.
func readBack(extName, key string, v *yaml.Node) (any, error) {
	str := func(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
	mapping := func(k string, v *yaml.Node) *yaml.Node {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{str(k), v}}
	}
	b, err := yaml.Marshal(mapping(extensionsKey, mapping(extName, mapping(key, v))))
	if err != nil {
		return nil, fmt.Errorf("can't write %s's value: %w", key, err)
	}
	vp, _ := configViper()
	vp.SetConfigType("yaml")
	if err := vp.ReadConfig(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("can't write %s's value: %w", key, err)
	}
	entry, err := extensionEntry(vp, extName)
	if err != nil {
		return nil, err
	}
	read, ok := entry[key]
	if !ok {
		return nil, fmt.Errorf("%s: a run can't read this key back from the config file", extensionKey(extName, key))
	}
	return read, nil
}

// emptyDocument is content without its null, when content is a document
// that holds nothing: comments, blank lines, at most one document start
// (---), and at most one null (null or ~), whose line keeps its comment. Each
// line ends with a newline, and a byte order mark that starts content is
// kept. Anything else is not such a document.
func emptyDocument(content []byte) ([]byte, bool) {
	var kept strings.Builder
	starts, nulls := 0, 0
	text, bom := strings.CutPrefix(string(content), "\ufeff")
	if bom {
		kept.WriteString("\ufeff")
	}
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return []byte(kept.String()), true
	}
	for _, line := range strings.Split(text, "\n") {
		value, comment, _ := strings.Cut(line, "#")
		switch strings.TrimSpace(value) {
		case "":
		case "---":
			starts++
			if comment != "" || starts > 1 {
				return nil, false
			}
		case "null", "Null", "NULL", "~":
			nulls++
			if nulls > 1 {
				return nil, false
			}
			if comment == "" {
				continue
			}
			line = "#" + comment
		default:
			return nil, false
		}
		kept.WriteString(line + "\n")
	}
	return []byte(kept.String()), true
}

// tryValue sets value, from the config file, on a copy of v, and returns the
// error that gives: nil when it takes it, and when no copy of v can be made
// or setting the copy panics.
func tryValue(v pflag.Value, key string, value any) (err error) {
	scratch := scratchValue(v)
	if scratch == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = nil
		}
	}()
	return setFlagsFromConfig([]*pflag.Flag{{Name: key, Value: scratch}}, key, value)
}

// pflagTypes makes a new value of each of pflag's own types whose value is a
// struct, by its Type.
var pflagTypes = map[string]func(fs *pflag.FlagSet){
	"stringSlice":    func(fs *pflag.FlagSet) { fs.StringSlice("v", nil, "") },
	"stringArray":    func(fs *pflag.FlagSet) { fs.StringArray("v", nil, "") },
	"intSlice":       func(fs *pflag.FlagSet) { fs.IntSlice("v", nil, "") },
	"int32Slice":     func(fs *pflag.FlagSet) { fs.Int32Slice("v", nil, "") },
	"int64Slice":     func(fs *pflag.FlagSet) { fs.Int64Slice("v", nil, "") },
	"uintSlice":      func(fs *pflag.FlagSet) { fs.UintSlice("v", nil, "") },
	"float32Slice":   func(fs *pflag.FlagSet) { fs.Float32Slice("v", nil, "") },
	"float64Slice":   func(fs *pflag.FlagSet) { fs.Float64Slice("v", nil, "") },
	"boolSlice":      func(fs *pflag.FlagSet) { fs.BoolSlice("v", nil, "") },
	"durationSlice":  func(fs *pflag.FlagSet) { fs.DurationSlice("v", nil, "") },
	"ipSlice":        func(fs *pflag.FlagSet) { fs.IPSlice("v", nil, "") },
	"stringToString": func(fs *pflag.FlagSet) { fs.StringToString("v", nil, "") },
	"stringToInt":    func(fs *pflag.FlagSet) { fs.StringToInt("v", nil, "") },
	"stringToInt64":  func(fs *pflag.FlagSet) { fs.StringToInt64("v", nil, "") },
}

// scratchValue is a new value of v's type, to try a value on without
// changing v: one of pflag's struct types by its Type, or a new value of any
// type that isn't a struct behind a pointer; nil for any other.
func scratchValue(v pflag.Value) pflag.Value {
	if define, ok := pflagTypes[v.Type()]; ok {
		fs := pflag.NewFlagSet("", pflag.ContinueOnError)
		define(fs)
		return fs.Lookup("v").Value
	}
	t := reflect.TypeOf(v)
	if t.Kind() != reflect.Pointer || t.Elem().Kind() == reflect.Struct {
		return nil
	}
	scratch, _ := reflect.New(t.Elem()).Interface().(pflag.Value)
	return scratch
}

// followLinks is path with every symbolic link it is resolved, the last
// included, even one whose target doesn't exist yet.
func followLinks(path string) string {
	for range 40 {
		fi, err := os.Lstat(path)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			return path
		}
		target, err := os.Readlink(path)
		if err != nil {
			return path
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		path = target
	}
	return path
}

// anchorOnTheWay is an error naming the first of the values the keys lead
// to, from m, that has a YAML anchor or is an alias. Writing there would
// drop an anchor that an alias elsewhere may name, or write into what an
// alias shares; keeping either would change what the rest of the file says,
// unannounced.
func anchorOnTheWay(m *yaml.Node, keys ...string) error {
	var path []string
	for _, key := range keys {
		var v *yaml.Node
		for i := 0; m.Kind == yaml.MappingNode && i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == key {
				v = m.Content[i+1]
				break
			}
		}
		if v == nil {
			return nil
		}
		path = append(path, key)
		switch {
		case v.Kind == yaml.AliasNode:
			return fmt.Errorf("%s is the YAML alias *%s, which upterm can't write through", strings.Join(path, "."), v.Value)
		case v.Anchor != "":
			return fmt.Errorf("%s has the YAML anchor &%s, which upterm can't keep when it writes there", strings.Join(path, "."), v.Anchor)
		}
		m = v
	}
	return nil
}

// mappingEntry is the mapping key holds in m, added to m, empty, when m has
// no such key or it holds nothing; an error when it holds anything else.
func mappingEntry(m *yaml.Node, key string) (*yaml.Node, error) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		v := m.Content[i+1]
		if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
			*v = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s is not a mapping", key)
		}
		return v, nil
	}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
	return v, nil
}

// setMappingValue sets key in m to v, in key's place when m has it, keeping
// the comments the old value had, or last.
func setMappingValue(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			old := m.Content[i+1]
			v.HeadComment, v.LineComment, v.FootComment = old.HeadComment, old.LineComment, old.FootComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

// replaceFile puts content at path: written to a file of mode 0600 in path's
// directory, which is created as needed, and renamed into place, so a reader
// sees the old file or the new one, never part of either.
func replaceFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	if _, err := f.Write(content); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}
	return nil
}
