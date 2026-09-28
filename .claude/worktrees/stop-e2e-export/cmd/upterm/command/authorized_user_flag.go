package command

import (
	"bytes"
	"encoding/csv"
	"strings"

	"github.com/spf13/pflag"
)

// authUserSliceValue is a pflag.Value (and pflag.SliceValue) for the five
// authorization-list flags: --authorized-user and the four legacy
// *-user flags.
//
// It exists because pflag's own stringSliceValue.Set parses with
// csv.Reader.Read, which returns only the first CSV record. A newline starts
// a second record, so "github:alice\ngithub:bob" silently becomes just
// "github:alice" inside pflag, before any upterm code ever sees the value —
// the dropped second entry is never fetched or authorized, and nothing
// errors. Because these five flags feed an authorization allow-list, a
// silently shortened value has to be a parse error instead, which is exactly
// what splitCSV already gives the environment/config path in root.go. This
// type makes the CLI path share that same parser so all three origins agree.
type authUserSliceValue struct {
	name    string
	value   *[]string
	changed bool
}

// newAuthUserSliceValue creates the flag value and seeds *p with val, mirroring
// pflag's own newStringSliceValue.
func newAuthUserSliceValue(name string, p *[]string, val []string) *authUserSliceValue {
	v := &authUserSliceValue{name: name, value: p}
	*v.value = val
	return v
}

// Set implements pflag.Value. It delegates to splitCSV — the same strict
// parser used for the UPTERM_ environment variable and the config file — so
// a newline is rejected here exactly as it already is there, rather than
// being silently truncated.
//
// Repeat-flag semantics match pflag's stringSliceValue: the first Set call
// replaces whatever default value was seeded in, and subsequent calls
// append, so `--authorized-user a --authorized-user b` yields both.
func (v *authUserSliceValue) Set(s string) error {
	elems, err := splitCSV(v.name, s)
	if err != nil {
		return err
	}

	if !v.changed {
		*v.value = elems
	} else {
		*v.value = append(*v.value, elems...)
	}
	v.changed = true
	return nil
}

// Type implements pflag.Value. It must stay "stringSlice": pflag's
// UnquoteUsage switches on this string to render the --help placeholder
// ("stringSlice" -> "strings"), and GenMarkdownTree/GenManTree bake that
// placeholder into the committed docs.
func (v *authUserSliceValue) Type() string { return "stringSlice" }

// String implements pflag.Value, formatting identically to pflag's own
// stringSliceValue.String() ("[" + CSV + "]") so --help output and the
// generated docs do not change.
func (v *authUserSliceValue) String() string {
	s, _ := writeAuthUserCSV(*v.value)
	return "[" + s + "]"
}

// Append implements pflag.SliceValue.
func (v *authUserSliceValue) Append(s string) error {
	*v.value = append(*v.value, s)
	return nil
}

// Replace implements pflag.SliceValue. Callers (bindFlagsToEnv) have already
// split the value with splitCSV or decoded it from YAML, so this assigns the
// elements directly rather than re-parsing them.
func (v *authUserSliceValue) Replace(elems []string) error {
	*v.value = elems
	return nil
}

// GetSlice implements pflag.SliceValue.
func (v *authUserSliceValue) GetSlice() []string {
	return *v.value
}

// writeAuthUserCSV mirrors pflag's own unexported writeAsCSV, so String()
// renders exactly like stringSliceValue.String() does.
func writeAuthUserCSV(vals []string) (string, error) {
	b := &bytes.Buffer{}
	w := csv.NewWriter(b)
	if err := w.Write(vals); err != nil {
		return "", err
	}
	w.Flush()
	return strings.TrimSuffix(b.String(), "\n"), nil
}

// registerAuthUserFlag registers one of the five authorization-list flags
// using authUserSliceValue instead of StringSliceVar.
//
// pflag's Flag.defaultIsZeroValue special-cases the concrete type
// *stringSliceValue so an empty default renders as no "(default ...)" text
// in --help. authUserSliceValue is a different concrete type, so it falls
// through to pflag's generic zero-value check, which does not know "[]"
// means empty. Clearing DefValue when the rendered default is the empty-list
// form reproduces the same suppression, keeping `make docs` output
// unchanged.
func registerAuthUserFlag(fs *pflag.FlagSet, p *[]string, name, usage string) {
	fs.Var(newAuthUserSliceValue(name, p, nil), name, usage)

	if f := fs.Lookup(name); f != nil && f.DefValue == "[]" {
		f.DefValue = ""
	}
}
