// Package testextension is an upterm Extension for tests that drive the built
// CLI, and the uptermd authority its runs register with: cmd/upterm-test is
// upterm composed with New, and cmd/uptermd-test is uptermd composed with an
// enabled test authority.
//
// It is configured through its environment, which a session process
// inherits from the upterm that started it, as package calls describes, and
// it logs what it was given in the lines calls defines.
package testextension

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/owenthereal/upterm/cmd/upterm/command"
	"github.com/owenthereal/upterm/host"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/testhelpers/testextension/calls"
	"github.com/owenthereal/upterm/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

// New is the test extension: the per-run flag --test-delegate, which makes a
// run delegated, the bound flag test-service, and a NormalizeName that
// lowercases a name, with a "-" for each space, and refuses one that starts
// with "Refused".
func New() *command.Extension {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("test-delegate", false, "Host the run as a delegated one, placed by the test extension.")
	fs.String("test-service", "", "The service the test extension's broker says it used.")
	return &command.Extension{
		Name: "test",
		HostFlags: []command.HostFlag{
			{Flag: fs.Lookup("test-delegate"), PerRun: true},
			{Flag: fs.Lookup("test-service")},
		},
		Prepare: prepare,
		Broker:  newBroker,
		Upgrade: func(c *cobra.Command) error {
			_, err := fmt.Fprintln(c.OutOrStdout(), calls.UpgradeLine)
			return err
		},
	}
}

func prepare(_ context.Context, opts command.HostOptions) (command.Prepared, error) {
	if text := os.Getenv(calls.PrepareErrorEnv); text != "" {
		return command.Prepared{}, errors.New(text)
	}
	if content, ok := os.LookupEnv(calls.RewriteConfigEnv); ok {
		if err := os.WriteFile(utils.UptermConfigFilePath(), []byte(content), 0o600); err != nil {
			return command.Prepared{}, err
		}
	}
	return command.Prepared{
		Delegated:     opts.Extension["test-delegate"].Value == "true",
		NormalizeName: normalizeName,
		Payload:       []byte(calls.Payload),
	}, nil
}

func normalizeName(name string) (string, error) {
	if strings.HasPrefix(name, "Refused") {
		return "", errors.New("the test extension refuses that name\nchoose another")
	}
	return strings.ReplaceAll(strings.ToLower(name), " ", "-"), nil
}

var logMu sync.Mutex

// logCall appends v, as a JSON line, to the file LogEnv names, if it names
// one.
func logCall(v any) error {
	path := os.Getenv(calls.LogEnv)
	if path == "" {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func newBroker(_ context.Context, h command.Handoff) (host.Broker, error) {
	call := calls.FactoryCall{
		Kind: "factory", Name: h.Name, Payload: string(h.Payload),
		Settings:  calls.Settings{ReadOnly: h.Settings.ReadOnly, ForceCommand: h.Settings.ForceCommand, Proxy: h.Settings.Proxy},
		Extension: flagValues(h.Options.Extension),
		Flags:     flagValues(h.Options.Flags),
	}
	for _, r := range h.Options.UserRefs {
		call.UserRefs = append(call.UserRefs, r.Flag+"="+r.Ref.Raw)
	}
	for _, f := range h.Options.AuthorizedKeys {
		call.AuthorizedKeys = append(call.AuthorizedKeys, len(f.Keys))
	}
	if err := logCall(call); err != nil {
		return nil, err
	}
	if text := os.Getenv(calls.FactoryErrorEnv); text != "" {
		return nil, errors.New(text)
	}
	var keys [][]byte
	for rest := []byte(os.Getenv(calls.KeysEnv)); len(rest) > 0; {
		key, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", calls.KeysEnv, err)
		}
		keys = append(keys, key.Marshal())
		rest = next
	}
	return broker{relay: os.Getenv(calls.RelayEnv), keys: keys}, nil
}

type broker struct {
	relay string
	keys  [][]byte
}

func (b broker) Place(_ context.Context, run host.Run) (host.Placement, error) {
	if err := logCall(calls.PlaceCall{Kind: "place", Name: run.Name, NameGenerated: run.NameGenerated, Command: run.Command,
		ForceCommand: run.ForceCommand, LoginCommand: run.LoginCommand, Capabilities: run.Capabilities}); err != nil {
		return host.Placement{}, err
	}
	if text := os.Getenv(calls.PlaceErrorEnv); text != "" {
		return host.Placement{}, errors.New(text)
	}
	id, err := uuid()
	if err != nil {
		return host.Placement{}, err
	}
	return host.Placement{
		RoutingID:    run.RoutingID,
		Relay:        b.relay,
		Trust:        host.InitialTrust{Keys: b.keys},
		Protocol:     calls.Protocol,
		ExternalID:   id,
		GuestAddress: run.Name,
		Association:  sessiondir.DelegationAssociation{Service: "https://authority.test", Account: "test-account", Login: "test-login"},
		Display:      sessiondir.DelegationDisplay{Authority: "Test authority"},
	}, nil
}

func flagValues(flags map[string]command.FlagValue) map[string]calls.FlagValue {
	out := make(map[string]calls.FlagValue, len(flags))
	for name, fv := range flags {
		out[name] = calls.FlagValue{Value: fv.Value, Source: string(fv.Source)}
	}
	return out
}

// uuid is a random version 4 UUID, in its canonical form.
func uuid() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
