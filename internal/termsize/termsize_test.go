package termsize

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Parse(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    Size
		wantErr bool
	}{
		{in: "132x43", want: Size{Cols: 132, Rows: 43}},
		{in: "80x24", want: Size{Cols: 80, Rows: 24}},
		{in: "65535x65535", want: Size{Cols: 65535, Rows: 65535}},
		{in: "132", wantErr: true},
		{in: "132x", wantErr: true},
		{in: "x43", wantErr: true},
		{in: "0x43", wantErr: true},
		{in: "132x0", wantErr: true},
		{in: "-1x43", wantErr: true},
		{in: "abcxdef", wantErr: true},
		{in: "", wantErr: true},
		// A pty winsize is uint16 on every platform; a larger value would wrap
		// silently into a tiny terminal.
		{in: "65536x24", wantErr: true},
		{in: "80x65536", wantErr: true},
	} {
		got, err := Parse(tc.in)
		if tc.wantErr {
			require.Error(t, err, "input %q", tc.in)
			continue
		}
		require.NoError(t, err, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}
