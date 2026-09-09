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
