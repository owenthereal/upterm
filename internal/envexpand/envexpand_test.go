package envexpand

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// unsetEnv removes keys for the duration of the test and restores their prior
// state afterwards. Go has t.Setenv but no t.Unsetenv, and cases that require
// a variable to be absent must not depend on the caller's environment.
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if old, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
		require.NoError(t, os.Unsetenv(k))
	}
}

func TestExpand(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		unset   []string
		in      string
		want    string
		wantErr string
	}{
		{
			name: "required reference is substituted",
			env:  map[string]string{"FLY_MACHINE_ID": "d891", "FLY_APP_NAME": "upterm"},
			in:   "${FLY_MACHINE_ID}.vm.${FLY_APP_NAME}.internal:2222",
			want: "d891.vm.upterm.internal:2222",
		},
		{
			name:    "required reference unset is an error naming the variable",
			unset:   []string{"FLY_MACHINE_ID"},
			in:      "${FLY_MACHINE_ID}.vm.internal",
			wantErr: `required variable "FLY_MACHINE_ID" is not set`,
		},
		{
			name:    "required reference set to empty is an error",
			env:     map[string]string{"FLY_MACHINE_ID": ""},
			in:      "${FLY_MACHINE_ID}",
			wantErr: `required variable "FLY_MACHINE_ID" is not set`,
		},
		{
			name:  "default is used when unset",
			unset: []string{"FLY_CONSUL_URL"},
			in:    "${FLY_CONSUL_URL:-}",
			want:  "",
		},
		{
			name: "default is used when set to empty",
			env:  map[string]string{"FLY_CONSUL_URL": ""},
			in:   "${FLY_CONSUL_URL:-fallback}",
			want: "fallback",
		},
		{
			name: "value wins over default when set",
			env:  map[string]string{"FLY_CONSUL_URL": "https://consul:8500"},
			in:   "${FLY_CONSUL_URL:-fallback}",
			want: "https://consul:8500",
		},
		{
			name:  "unset without default is distinct from set-to-empty with default",
			unset: []string{"FLY_CONSUL_URL"},
			in:    "${FLY_CONSUL_URL:-fallback}",
			want:  "fallback",
		},
		{
			name: "bare dollar is literal",
			env:  map[string]string{"USER": "owen"},
			in:   "pa$USER-word and cost: $5",
			want: "pa$USER-word and cost: $5",
		},
		{
			name: "double dollar brace escapes a literal reference",
			env:  map[string]string{"NAME": "substituted"},
			in:   "literal $${NAME} here",
			want: "literal ${NAME} here",
		},
		{
			name: "escape output is not rescanned",
			env:  map[string]string{"TOKEN": "secret"},
			in:   "$${TOKEN}",
			want: "${TOKEN}",
		},
		{
			name: "substituted content is not rescanned",
			env:  map[string]string{"OUTER": "${TOKEN}", "TOKEN": "secret"},
			in:   "${OUTER}",
			want: "${TOKEN}",
		},
		{
			name: "no references passes through untouched",
			in:   "[::]:2222",
			want: "[::]:2222",
		},
		{
			name:    "unterminated reference is an error",
			in:      "${FLY_APP_NAME",
			wantErr: "unterminated variable reference",
		},
		{
			name:    "empty name is an error",
			in:      "${}",
			wantErr: "empty variable name",
		},
		{
			name:    "empty name with default is an error",
			in:      "${:-x}",
			wantErr: "empty variable name",
		},
		{
			name:    "invalid name character is an error that does not echo the name",
			in:      "${FLY-APP-NAME}",
			wantErr: "invalid variable name in reference at offset 0",
		},
		{
			name:    "leading digit in name is an error",
			in:      "${1ABC}",
			wantErr: "invalid variable name in reference at offset 0",
		},
		{
			name:    "nested reference in default is an error",
			env:     map[string]string{"A": "", "B": "b"},
			in:      "${A:-${B}}",
			wantErr: "nested variable reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsetEnv(t, tt.unset...)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			got, err := Expand(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// Expansion errors reach stderr and slog. A malformed reference inside a
// credential must not copy the surrounding secret into the message.
//
// The sentinel is placed INSIDE the malformed reference in all three cases on
// purpose. An earlier draft put it before the "${" in the empty-name case,
// which let both leaking implementations pass: the unterminated message quoted
// s[i:] (everything from "$" onward), and the invalid-name message quoted the
// rejected name, but the empty-name case had nothing to leak. Placing the
// sentinel inside ${:-<secret>} catches implementations that echo the reference
// body or default text.
func TestExpandErrorsDoNotLeakValueContents(t *testing.T) {
	const secret = "sup3rs3cr3t"

	malformed := map[string]string{
		// Quoting s[i:] would echo everything from "${" onward.
		"unterminated": "https://user@host/${BROKEN-" + secret,
		// Quoting the rejected name would echo the name's contents.
		"invalid name": "https://user@host/${BAD-" + secret + "}",
		// Echoing the reference body or default text would expose the sentinel.
		"empty name": "https://user@host/${:-" + secret + "}",
	}

	for name, in := range malformed {
		t.Run(name, func(t *testing.T) {
			_, err := Expand(in)

			require.Error(t, err)
			require.NotContains(t, err.Error(), secret)
		})
	}
}
