package command

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/envexpand"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/sourcecheck"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/server"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Root is the uptermd command.
func Root() *cobra.Command {
	return RootWith(nil)
}

// Extension is what a relay built on uptermd adds to it, compiled in. Its
// flags and commands join uptermd's, and New builds what it adds to the
// server.
type Extension struct {
	// Name names the extension in errors. It is required with New.
	Name string
	// Flags registers the extension's flags on uptermd's persistent flags.
	// They are read through Config, from the command line, the UPTERMD_
	// environment or the config file, exactly as uptermd's own are.
	Flags func(*pflag.FlagSet)
	// Commands are subcommands to add, for operators. They read
	// configuration with ConfigFor.
	Commands func() []*cobra.Command
	// New builds the server's extensions, once, after configuration and
	// logging are ready and before anything listens. An error stops uptermd.
	New func(ctx context.Context, cfg Config) (server.Extensions, error)
}

// Config is uptermd's resolved configuration, as an extension sees it.
type Config struct {
	// Opt is resolved exactly as uptermd resolves its own, NodeID and BootID
	// included.
	Opt server.Opt
	// Logger is the server's logger when New is given the Config, and from
	// ConfigFor a console logger that honours --debug.
	Logger *slog.Logger
	// NodeID is --node-id.
	NodeID string
	// BootID is a fresh random UUID each time uptermd starts. ConfigFor,
	// which starts nothing, leaves it empty.
	BootID string

	v       *viper.Viper
	extName string
	flags   map[string]bool // the extension's own flags
}

// String is the value of the extension's flag name, its ${VAR} references
// expanded once.
func (c Config) String(name string) (string, error) {
	if err := c.own(name); err != nil {
		return "", err
	}
	return envexpand.Expand(c.v.GetString(name))
}

// Bool is the value of the extension's bool flag name. A value given as a
// string, as the environment gives one, has its ${VAR} references expanded
// once first.
func (c Config) Bool(name string) (bool, error) {
	if err := c.own(name); err != nil {
		return false, err
	}
	s, ok := c.v.Get(name).(string)
	if !ok {
		return c.v.GetBool(name), nil
	}
	s, err := envexpand.Expand(s)
	if err != nil {
		return false, err
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

// own refuses a name that isn't one of the extension's flags: uptermd's own
// are in Opt.
func (c Config) own(name string) error {
	if !c.flags[name] {
		return fmt.Errorf("%s is not a flag of extension %s", name, c.extName)
	}
	return nil
}

// extensionAnnotation marks the root command an extension was composed into,
// and each of the extension's flags, with the extension's name.
const extensionAnnotation = "uptermd-extension"

// newConfig is the Config of opt, resolved from v for cmd.
func newConfig(cmd *cobra.Command, v *viper.Viper, opt server.Opt, logger *slog.Logger) Config {
	cfg := Config{Opt: opt, Logger: logger, NodeID: opt.NodeID, BootID: opt.BootID, v: v, flags: map[string]bool{}}
	cfg.extName = cmd.Root().Annotations[extensionAnnotation]
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if _, ok := f.Annotations[extensionAnnotation]; ok {
			cfg.flags[f.Name] = true
		}
	})
	return cfg
}

// ConfigFor resolves uptermd's configuration inside cmd, a subcommand of a
// command RootWith built, as uptermd would resolve it to start.
func ConfigFor(cmd *cobra.Command) (Config, error) {
	v, opt, err := resolveConfig(cmd)
	if err != nil {
		return Config{}, err
	}
	options := []logging.Option{logging.Console()}
	if opt.Debug {
		options = append(options, logging.Debug())
	}
	logger, err := logging.New(options...)
	if err != nil {
		return Config{}, err
	}
	return newConfig(cmd, v, opt, logger.Logger), nil
}

// reservedCommands are the subcommands uptermd has, or cobra adds.
var reservedCommands = []string{"version", "help", "completion"}

// RootWith is the uptermd command composed with ext, which may be nil. It
// panics if ext names a flag or command uptermd already uses, or has New and
// no Name.
func RootWith(ext *Extension) *cobra.Command {
	rootCmd := &rootCmd{ext: ext}
	cmd := &cobra.Command{
		Use:   "uptermd",
		Short: "Upterm Daemon",
		RunE:  rootCmd.RunE,
	}

	cmd.PersistentFlags().Duration("handshake-timeout", server.DefaultHandshakeTimeout, "SSH establishment budget (half downstream, half upstream dial and handshake)")
	cmd.PersistentFlags().String("config", "", "server config")

	cmd.PersistentFlags().String("ssh-network", "tcp", "network for the SSH listener: tcp (the address's own families), tcp4 or tcp6")
	cmd.PersistentFlags().Bool("ssh-proxy-protocol-required", false, "require a PROXY protocol v2 header on every SSH connection, and close any connection without one. Needs --internal-addr. Only as trustworthy as the network: make sure nothing but your proxy can reach this listener")
	cmd.PersistentFlags().StringP("ssh-addr", "", utils.DefaultLocalhost("2222"), "ssh server address")
	cmd.PersistentFlags().StringP("ws-addr", "", "", "websocket server address")
	cmd.PersistentFlags().StringP("node-addr", "", "", "node address")
	cmd.PersistentFlags().String("node-id", "", "this node's ID in its fleet, for logs and for extensions that need one, such as ${FLY_MACHINE_ID}; at most 128 letters, digits, '.', '_' and '-'")
	cmd.PersistentFlags().StringP("internal-addr", "", "", "address for the internal listener that node hops and bridged WebSocket guests use; only other relay nodes should be able to reach it. When set, the public SSH listener refuses relay certificates")
	cmd.PersistentFlags().StringSliceP("authorized-keys", "", nil, "authorized_keys file(s) controlling which public keys may register as hosts; may be repeated, mirroring OpenSSH's AuthorizedKeysFile directive")
	cmd.PersistentFlags().StringSlice("deny-source", nil, "refuse connections from this source address or CIDR; may be repeated. Checked on the SSH listener after any PROXY header, at the WebSocket upgrade, at host registration and on node hops. Behind a proxy that sends no PROXY header the source is the proxy, and on a listener shared with other nodes it can be a node, so don't list fleet addresses")
	cmd.PersistentFlags().StringSlice("hop-key", nil, "private key file(s) that sign node hops; the first signs. Without it, hops are signed with the server's own keys. Hosts are always sent certificates signed with the server's own keys")
	cmd.PersistentFlags().StringSlice("hop-trusted-key", nil, "public key(s) whose signatures this node accepts on node hops, in addition to its hop keys")
	cmd.PersistentFlags().StringSlice("node-trusted-key", nil, "public key(s) this node accepts from another relay node it hops to, in addition to its own server keys. Add a new server key here on every node before any node presents it, and keep the old one listed until no node presents it")
	cmd.PersistentFlags().Bool("hop-refuse-host-key", false, "stop accepting node hops signed with the server's own keys")
	cmd.PersistentFlags().Bool("legacy-hops", true, "exchange node hops in the format that predates the hop gate, so this node can share a fleet with older ones; turn it off only once every node supports the gate")
	cmd.PersistentFlags().StringSliceP("private-key", "", nil, "server private key")
	cmd.PersistentFlags().StringSliceP("hostname", "", nil, "server hostname for public-key authentication certificate principals. If empty, public-key authentication is used instead.")
	cmd.PersistentFlags().BoolP("ssh-proxy-protocol", "", false, "enable PROXY protocol support for the SSH listener (for use behind TCP proxies like Traefik, HAProxy, or AWS ELB)")

	cmd.PersistentFlags().StringP("network", "", "mem", "network provider")
	cmd.PersistentFlags().StringSliceP("network-opt", "", nil, "network provider option")

	cmd.PersistentFlags().StringP("metric-addr", "", "", "metric server address")
	cmd.PersistentFlags().BoolP("debug", "", os.Getenv("DEBUG") != "", "debug")

	cmd.PersistentFlags().String("routing", string(routing.ModeEmbedded), "session routing mode: embedded, consul, or auto (consul when consul-url is set, otherwise embedded)")
	cmd.PersistentFlags().String("consul-url", "", "consul URL for routing mode 'consul'")
	cmd.PersistentFlags().String("consul-session-ttl", server.DefaultSessionTTL.String(), "consul session TTL for routing mode 'consul'")

	cmd.PersistentFlags().String("sentry-dsn", "", "Sentry DSN for error tracking")

	cmd.AddCommand(versionCmd())

	if ext != nil {
		compose(cmd, ext)
	}

	return cmd
}

// compose adds ext's flags and commands to cmd.
func compose(cmd *cobra.Command, ext *Extension) {
	if ext.New != nil && ext.Name == "" {
		panic("uptermd: an extension with New needs a Name")
	}
	cmd.Annotations = map[string]string{extensionAnnotation: ext.Name}
	if ext.Flags != nil {
		fs := pflag.NewFlagSet(ext.Name, pflag.ContinueOnError)
		ext.Flags(fs)
		fs.VisitAll(func(f *pflag.Flag) {
			// A name uptermd has would otherwise panic in AddFlag with
			// pflag's terser message, and help, which cobra adds only when
			// the command runs, would take the place of cobra's.
			if f.Name == "help" || cmd.PersistentFlags().Lookup(f.Name) != nil {
				panic(fmt.Sprintf("uptermd: extension %s: flag %q is uptermd's", ext.Name, f.Name))
			}
			if f.Annotations == nil {
				f.Annotations = map[string][]string{}
			}
			f.Annotations[extensionAnnotation] = []string{ext.Name}
			cmd.PersistentFlags().AddFlag(f)
		})
	}
	if ext.Commands != nil {
		for _, c := range ext.Commands() {
			if slices.Contains(reservedCommands, c.Name()) {
				panic(fmt.Sprintf("uptermd: extension %s: command %q is uptermd's", ext.Name, c.Name()))
			}
			cmd.AddCommand(c)
		}
	}
}

type rootCmd struct {
	ext *Extension
}

func (cmd *rootCmd) RunE(c *cobra.Command, args []string) error {
	v, opt, err := resolveConfig(c)
	if err != nil {
		return err
	}
	// Before an extension is given them; Start validates the rest.
	if err := sourcecheck.Check(opt.NodeID, opt.DenySources); err != nil {
		return fmt.Errorf("uptermd: %w", err)
	}

	logOptions := []logging.Option{logging.Console()}
	if opt.Debug {
		logOptions = append(logOptions, logging.Debug())
	}
	if opt.SentryDSN != "" {
		logOptions = append(logOptions, logging.Sentry(opt.SentryDSN))
	}

	logger, err := logging.New(logOptions...)
	if err != nil {
		return err
	}
	defer func() {
		_ = logger.Close()
	}()

	c.SetContext(uptermctx.WithLogger(c.Context(), logger))

	bootID, err := newBootID()
	if err != nil {
		return err
	}
	opt.BootID = bootID
	// started records the error the extension's Lifecycle failed to start
	// with, which the server returns as it is, so it can be told apart and
	// named after the extension.
	var started *startedLifecycle
	if ext := cmd.ext; ext != nil && ext.New != nil {
		extensions, err := ext.New(c.Context(), newConfig(c, v, opt, logger.Logger))
		if err != nil {
			return fmt.Errorf("uptermd: extension %s: %w", ext.Name, err)
		}
		if err := checkListenersForAuthority(opt, extensions); err != nil {
			return fmt.Errorf("uptermd: %w", err)
		}
		if extensions.Lifecycle != nil {
			started = &startedLifecycle{Lifecycle: extensions.Lifecycle}
			extensions.Lifecycle = started
		}
		opt.Extensions = extensions
	}

	// Start covers the whole lifetime, so this is no longer only a startup
	// failure: a shutdown that could not delete this node's sessions arrives
	// here too, and calling that "failed to start" sends whoever reads the log
	// to the wrong end of the run.
	if err := server.Start(c.Context(), opt, logger.Logger); err != nil {
		logger.Error("uptermd exited with an error", "error", err)
		if failed := started.failure(); failed != nil && errors.Is(err, failed) {
			return fmt.Errorf("uptermd: extension %s: %w", cmd.ext.Name, failed)
		}
		return fmt.Errorf("uptermd: %w", err)
	}

	return nil
}

// The refusals of an enabled authority without the listener options that
// make its hosts' sources trustworthy, which only the command can check:
// they exist only as options of the listener it opens.
var (
	errAuthorityNeedsTCP4  = errors.New("an enabled authority needs --ssh-network tcp4")
	errAuthorityNeedsPROXY = errors.New("an enabled authority needs --ssh-proxy-protocol-required")
)

// checkListenersForAuthority refuses an enabled authority whose public SSH
// listener isn't IPv4 alone, behind a PROXY header that is required. The
// server checks the rest of what an enabled authority needs as it starts.
func checkListenersForAuthority(opt server.Opt, extensions server.Extensions) error {
	if extensions.Authority == nil || !extensions.Enabled {
		return nil
	}
	if opt.SSHNetwork != "tcp4" {
		return errAuthorityNeedsTCP4
	}
	if !opt.SSHProxyProtocolRequired {
		return errAuthorityNeedsPROXY
	}
	return nil
}

// startedLifecycle is an extension's Lifecycle, recording the error its
// Start returned.
type startedLifecycle struct {
	server.Lifecycle

	mu  sync.Mutex
	err error
}

func (l *startedLifecycle) Start(ctx context.Context, rt server.Runtime) error {
	err := l.Lifecycle.Start(ctx, rt)
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
	return err
}

// failure is the error Start returned; nil if it succeeded, never ran, or l
// is nil.
func (l *startedLifecycle) failure() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// newBootID is a random version 4 UUID, in canonical lowercase form.
func newBootID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 9562 variant
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// resolveConfig decodes cmd's flags into a server.Opt, each from the command
// line, the UPTERMD_ environment or the --config file, in that order of
// precedence, and expands its ${VAR} references. It returns the Viper
// instance it decoded from as well, which an extension's flags are read from.
func resolveConfig(cmd *cobra.Command) (*viper.Viper, server.Opt, error) {
	var opt server.Opt
	v := viper.New()

	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		flagName := flag.Name
		if flagName != "config" && flagName != "help" {
			if err := v.BindPFlag(flagName, flag); err != nil {
				panic(fmt.Errorf("error binding flag '%s': %w", flagName, err).Error())
			}
		}
	})

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.SetEnvPrefix("UPTERMD")

	// Bind SENTRY_DSN directly (standard convention), with UPTERMD_SENTRY_DSN as fallback
	_ = v.BindEnv("sentry-dsn", "SENTRY_DSN", "UPTERMD_SENTRY_DSN")

	cfgFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return nil, opt, err
	}

	if _, err := os.Stat(cfgFile); err == nil {
		v.SetConfigFile(cfgFile)
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, opt, fmt.Errorf("error loading config file %s: %w", cfgFile, err)
		}
	}

	if err := v.Unmarshal(&opt); err != nil {
		return nil, opt, err
	}
	// RefuseLegacyHops is the opposite of --legacy-hops, so that its zero
	// value, for a program that builds an Opt itself, is today's. It is
	// decoded as Opt's own bools are, so a value that isn't one fails.
	var hops struct {
		LegacyHops bool `mapstructure:"legacy-hops"`
	}
	if err := v.Unmarshal(&hops); err != nil {
		return nil, opt, err
	}
	opt.RefuseLegacyHops = !hops.LegacyHops

	// Expand ${VAR} references after decoding rather than via a mapstructure
	// decode hook: this keeps expansion ordered explicitly after viper's list
	// splitting, guarantees it runs exactly once per value, and leaves viper's
	// own decode hooks untouched.
	if err := envexpand.ExpandStruct(&opt); err != nil {
		return nil, opt, err
	}
	return v, opt, nil
}
