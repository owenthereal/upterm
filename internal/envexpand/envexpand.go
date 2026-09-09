// Package envexpand expands environment variable references in configuration
// values.
//
// uptermd images are built on gcr.io/distroless/static, which has no shell, so
// values that need a runtime-discovered component (a machine ID, a pod IP)
// cannot be interpolated before the process starts. This package performs that
// interpolation in-process.
//
// It deliberately does not use os.Expand or os.ExpandEnv: those treat a bare
// "$" as a reference and silently substitute the empty string for unset names,
// both of which corrupt credentials and hide misconfiguration.
package envexpand

import (
	"fmt"
	"os"
	"reflect"
	"strings"
)

// Expand expands variable references in s against the process environment and
// returns the result. Substituted values are never rescanned, so a value that
// itself contains "${...}" is left alone.
//
// Supported syntax:
//
//	${NAME}            required; an error if NAME is unset or empty
//	${NAME:-default}   default is used when NAME is unset or empty
//	$${               a literal "${"
//
// A "$" not followed by "{" is always literal.
func Expand(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}

		// "$${" escapes a literal "${". The result is not rescanned.
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("${")
			i += 3
			continue
		}

		// A "$" that does not open a reference is literal.
		if !strings.HasPrefix(s[i:], "${") {
			b.WriteByte('$')
			i++
			continue
		}

		start := i
		close := strings.IndexByte(s[i:], '}')
		if close < 0 {
			// Report the position only. The remainder of the value may be a
			// password.
			return "", fmt.Errorf("unterminated variable reference at offset %d", start)
		}
		ref := s[i+2 : i+close]
		i += close + 1

		name, def := ref, ""
		hasDefault := false
		if j := strings.Index(ref, ":-"); j >= 0 {
			name, def, hasDefault = ref[:j], ref[j+2:], true
		}

		// Validate before any message can quote the name, so malformed text
		// lifted out of a credential is never echoed.
		if err := validateName(name, start); err != nil {
			return "", err
		}

		// "${A:-${B}}" closes on the inner brace, leaving "${B" in the default.
		// Reject it rather than inventing semantics for nesting. The name is
		// safe to quote here: it has passed validateName.
		if strings.Contains(def, "${") {
			return "", fmt.Errorf("nested variable reference in default for %q is not supported", name)
		}

		value := os.Getenv(name)
		if value == "" {
			if !hasDefault {
				return "", fmt.Errorf("required variable %q is not set", name)
			}
			value = def
		}
		b.WriteString(value)
	}

	return b.String(), nil
}

// validateName rejects anything that is not a conventional environment
// variable name, so that a stray "${" in a credential fails loudly instead of
// being silently reinterpreted.
//
// Messages carry the offset rather than the offending text: an invalid "name"
// is by definition text the caller did not intend as a reference, which in a
// DSN or password is secret material.
func validateName(name string, offset int) error {
	if name == "" {
		return fmt.Errorf("empty variable name in reference at offset %d", offset)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return fmt.Errorf("invalid variable name in reference at offset %d", offset)
		}
	}
	return nil
}

// ExpandStruct expands every string and []string field of the struct pointed
// to by v, in place. Each field is expanded exactly once.
//
// Fields are matched on reflect.Kind rather than by type assertion so that
// named string types — routing.Mode, for example — are covered.
func ExpandStruct(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("envexpand: want a non-nil pointer to struct, got %T", v)
	}

	st := rv.Elem()
	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		if !field.CanSet() {
			continue
		}
		name := st.Type().Field(i).Name

		switch {
		case field.Kind() == reflect.String:
			out, err := Expand(field.String())
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			field.SetString(out)

		case field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.String:
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				out, err := Expand(elem.String())
				if err != nil {
					return fmt.Errorf("%s[%d]: %w", name, j, err)
				}
				elem.SetString(out)
			}
		}
	}

	return nil
}
