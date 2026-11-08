package sourcecheck

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	require.NoError(t, Check("", nil))
	require.NoError(t, Check(strings.Repeat("a", 128), []string{"203.0.113.0/24", "2001:db8::1"}))
	require.EqualError(t, Check(strings.Repeat("a", 129), nil), `--node-id "`+strings.Repeat("a", 129)+`": use at most 128 letters, digits, '.', '_' and '-'`)
	// The node ID is reported first.
	require.EqualError(t, Check("a b", []string{"nope"}), `--node-id "a b": use at most 128 letters, digits, '.', '_' and '-'`)
	require.EqualError(t, Check("machine-1", []string{"192.0.2.1", "nope"}), `--deny-source "nope": not an IP address or CIDR`)
}
