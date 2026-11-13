package command

import (
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// pairValue is a pflag.Value of upterm's own making: two strings, set as
// "a/b".
type pairValue struct{ a, b string }

func (p *pairValue) Set(s string) error {
	a, b, ok := strings.Cut(s, "/")
	if !ok {
		return errors.New("want a/b")
	}
	p.a, p.b = a, b
	return nil
}
func (p *pairValue) String() string { return p.a + "/" + p.b }
func (p *pairValue) Type() string   { return "pair" }

// extFlagCase is an extension's host flag, test-x, and how the parent comes
// to hold its value.
type extFlagCase struct {
	// define defines test-x in fs and returns the variable it is bound to.
	define func(fs *pflag.FlagSet) any
	// set gives the parent's flag its value, as the command line, the
	// environment or the config file would; nil leaves it at its default.
	set func(f *pflag.Flag) error
}

// sets is a set that makes each of values a Set call, as a flag repeated
// on the command line is.
func sets(values ...string) func(*pflag.Flag) error {
	return func(f *pflag.Flag) error {
		for _, v := range values {
			if err := f.Value.Set(v); err != nil {
				return err
			}
		}
		return nil
	}
}

// replaces is a set that replaces a slice flag's elements, as a list in the
// config file or the environment does.
func replaces(elems ...string) func(*pflag.Flag) error {
	return func(f *pflag.Flag) error { return f.Value.(pflag.SliceValue).Replace(elems) }
}

func extFlagCases() map[string]extFlagCase {
	def := func(define func(fs *pflag.FlagSet) any, set func(*pflag.Flag) error) extFlagCase {
		return extFlagCase{define: define, set: set}
	}
	str := func(d string) func(fs *pflag.FlagSet) any {
		return func(fs *pflag.FlagSet) any { var v string; fs.StringVar(&v, "test-x", d, ""); return &v }
	}
	strSlice := func(d ...string) func(fs *pflag.FlagSet) any {
		return func(fs *pflag.FlagSet) any { var v []string; fs.StringSliceVar(&v, "test-x", d, ""); return &v }
	}
	strArray := func(d ...string) func(fs *pflag.FlagSet) any {
		return func(fs *pflag.FlagSet) any { var v []string; fs.StringArrayVar(&v, "test-x", d, ""); return &v }
	}
	strMap := func(d map[string]string) func(fs *pflag.FlagSet) any {
		return func(fs *pflag.FlagSet) any {
			var v map[string]string
			fs.StringToStringVar(&v, "test-x", d, "")
			return &v
		}
	}
	intMap := func(d map[string]int) func(fs *pflag.FlagSet) any {
		return func(fs *pflag.FlagSet) any { var v map[string]int; fs.StringToIntVar(&v, "test-x", d, ""); return &v }
	}
	int64Map := func(d map[string]int64) func(fs *pflag.FlagSet) any {
		return func(fs *pflag.FlagSet) any {
			var v map[string]int64
			fs.StringToInt64Var(&v, "test-x", d, "")
			return &v
		}
	}
	tricky := []string{" a", "", "b,c", "d ", `"e"`}
	return map[string]extFlagCase{
		// The scalars, and a value of the extension's own type.
		"string":               def(str(""), sets(` a, b=c "d" `)),
		"string, default left": def(str("dflt"), nil),
		"bool":                 def(func(fs *pflag.FlagSet) any { var v bool; fs.BoolVar(&v, "test-x", false, ""); return &v }, sets("true")),
		"int":                  def(func(fs *pflag.FlagSet) any { var v int; fs.IntVar(&v, "test-x", 0, ""); return &v }, sets("-7")),
		"uint":                 def(func(fs *pflag.FlagSet) any { var v uint; fs.UintVar(&v, "test-x", 0, ""); return &v }, sets("7")),
		"float64":              def(func(fs *pflag.FlagSet) any { var v float64; fs.Float64Var(&v, "test-x", 0, ""); return &v }, sets("0.1")),
		"duration":             def(func(fs *pflag.FlagSet) any { var v time.Duration; fs.DurationVar(&v, "test-x", 0, ""); return &v }, sets("1h2m3.5s")),
		"ip":                   def(func(fs *pflag.FlagSet) any { var v net.IP; fs.IPVar(&v, "test-x", nil, ""); return &v }, sets("::1")),
		"ip, no default left":  def(func(fs *pflag.FlagSet) any { var v net.IP; fs.IPVar(&v, "test-x", nil, ""); return &v }, nil),
		"its own type":         def(func(fs *pflag.FlagSet) any { v := &pairValue{}; fs.Var(v, "test-x", ""); return v }, sets("x,y/z")),

		// The slices, with elements a list can only hold exactly: spaces at
		// their ends, an empty one, a comma, quotes.
		"stringSlice":                        def(strSlice(), replaces(tricky...)),
		"stringSlice, from the command line": def(strSlice(), sets(`" a","b "`, `"c,d",`)),
		"stringSlice, one empty element":     def(strSlice(), replaces("")),
		"stringSlice, emptied":               def(strSlice("d"), replaces()),
		"stringSlice, default set":           def(strSlice("d1", "d2"), replaces("x")),
		"stringSlice, default left":          def(strSlice("d1", "d 2"), nil),
		"stringArray":                        def(strArray(), sets(tricky...)),
		"stringArray, one empty element":     def(strArray(), sets("")),
		"stringArray, default left":          def(strArray("d,1"), nil),
		"intSlice":                           def(func(fs *pflag.FlagSet) any { var v []int; fs.IntSliceVar(&v, "test-x", nil, ""); return &v }, sets("1,-2", "3")),
		"int32Slice":                         def(func(fs *pflag.FlagSet) any { var v []int32; fs.Int32SliceVar(&v, "test-x", nil, ""); return &v }, sets("1,-2")),
		"int64Slice":                         def(func(fs *pflag.FlagSet) any { var v []int64; fs.Int64SliceVar(&v, "test-x", nil, ""); return &v }, sets("9000000000")),
		"uintSlice":                          def(func(fs *pflag.FlagSet) any { var v []uint; fs.UintSliceVar(&v, "test-x", nil, ""); return &v }, sets("1,2")),
		"float32Slice":                       def(func(fs *pflag.FlagSet) any { var v []float32; fs.Float32SliceVar(&v, "test-x", nil, ""); return &v }, sets("0.1,2.5")),
		"float64Slice":                       def(func(fs *pflag.FlagSet) any { var v []float64; fs.Float64SliceVar(&v, "test-x", nil, ""); return &v }, sets("0.1,1e-9")),
		"boolSlice":                          def(func(fs *pflag.FlagSet) any { var v []bool; fs.BoolSliceVar(&v, "test-x", nil, ""); return &v }, sets("true,false")),
		"durationSlice": def(func(fs *pflag.FlagSet) any {
			var v []time.Duration
			fs.DurationSliceVar(&v, "test-x", nil, "")
			return &v
		}, sets("1s,2m3.5s")),
		"ipSlice": def(func(fs *pflag.FlagSet) any { var v []net.IP; fs.IPSliceVar(&v, "test-x", nil, ""); return &v }, sets("10.0.0.1,::1")),
		"durationSlice, default left": def(func(fs *pflag.FlagSet) any {
			var v []time.Duration
			fs.DurationSliceVar(&v, "test-x", []time.Duration{time.Second}, "")
			return &v
		}, nil),

		// The maps, with values that hold what their syntax uses: a comma,
		// an equals sign, quotes, and spaces at the end.
		"stringToString":                        def(strMap(nil), sets(`"k=a,b=c""d","e=f ","g=""h"""`)),
		"stringToString, one entry":             def(strMap(nil), sets("region=west")),
		"stringToString, one entry with quotes": def(strMap(nil), sets(`"k=""v""","k=""v"""`)),
		"stringToString, repeated":              def(strMap(nil), sets("a=1", `"b=2,3","c=4"`)),
		"stringToString, default set":           def(strMap(map[string]string{"a": "b"}), sets("x=y")),
		"stringToString, default left":          def(strMap(map[string]string{"a": "b"}), nil),
		"stringToString, empty default left":    def(strMap(map[string]string{}), nil),
		"stringToInt":                           def(intMap(nil), sets("port=8080", "n=-1")),
		"stringToInt, empty default left":       def(intMap(map[string]int{}), nil),
		"stringToInt64":                         def(int64Map(nil), sets("big=9000000000")),
		"stringToInt64, default left":           def(int64Map(map[string]int64{"a": 1}), nil),
	}
}

// hostWith is upterm host's command in a tree composed with an extension
// whose one host flag tc defines, and that flag's variable.
func hostWith(t *testing.T, tc extFlagCase) (*cobra.Command, any) {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	v := tc.define(fs)
	host, _, err := RootWith(&Extension{Name: "test", HostFlags: []HostFlag{{Flag: fs.Lookup("test-x")}}}).Find([]string{"host"})
	require.NoError(t, err)
	require.NoError(t, host.ParseFlags(nil))
	return host, v
}

// Every type of flag an extension can add reaches a delegated run's session
// process holding exactly the value the parent had, whether the parent set
// it or left it at its default.
func TestExtensionFlagsReachTheSessionProcessExactly(t *testing.T) {
	for name, tc := range extFlagCases() {
		t.Run(name, func(t *testing.T) {
			restoreFlags(t)
			parent, want := hostWith(t, tc)
			if tc.set != nil {
				require.NoError(t, tc.set(parent.Flags().Lookup("test-x")))
			}
			opts, err := buildHostOptions(parent)
			require.NoError(t, err)
			enc, err := encodeHandoff(Handoff{Name: "x", Options: opts}, exactValues(parent))
			require.NoError(t, err)
			d := readHandoff(enc)
			require.NoError(t, d.err)

			session, got := hostWith(t, tc)
			applyExtensionFlags(session, d)
			require.NoError(t, d.err)
			require.Equal(t, reflect.ValueOf(want).Elem().Interface(), reflect.ValueOf(got).Elem().Interface())
			// The int maps' String lists their entries in no fixed order.
			if typ := parent.Flags().Lookup("test-x").Value.Type(); !strings.HasPrefix(typ, "stringToInt") {
				require.Equal(t, parent.Flags().Lookup("test-x").Value.String(), session.Flags().Lookup("test-x").Value.String())
			}
		})
	}
}
