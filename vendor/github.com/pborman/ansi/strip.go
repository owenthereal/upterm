package ansi

import (
	"fmt"
	"strings"
)

// An errorList is simply a list of errors.
type errorList []error

func (e errorList) Error() string {
	if len(e) == 0 {
		return ""
	}
	parts := make([]string, len(e))
	for x, err := range e {
		parts[x] = err.Error()
	}
	return strings.Join(parts, "\n")
}

func (e errorList) err() error {
	switch len(e) {
	case 0:
		return nil
	case 1:
		return e[0]
	default:
		return e
	}
}

// Strip returns in with all ANSI escape sequences stripped.  An error is
// also returned if one or more of the stripped escape sequences are invalid.
func Strip(in []byte) ([]byte, error) {
	var errs errorList
	var out []string
	var s *S
	var err error
	for len(in) > 0 {
		in, s, err = Decode(in)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q: %v", s, err))
		}
		// If s.Type is "" then s represents plain text and not
		// an escape sequence.  We are only interested in plain
		// text.
		if s.Type == "" {
			out = append(out, string(s.Code))
		}
	}
	if len(out) > 0 {
		return []byte(strings.Join(out, "")), errs.err()
	}
	return nil, errs.err()
}
