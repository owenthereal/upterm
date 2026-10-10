package join

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorsMatchTheirSentinel(t *testing.T) {
	cause := errors.New("cause")

	for _, tc := range []struct {
		err      error
		sentinel error
		other    error
	}{
		{&RefusedError{}, ErrKeysRefused, ErrIdentity},
		{&RefusedError{TooMany: true, Ambiguous: true}, ErrKeysRefused, ErrHostKey},
		{&IdentityError{Key: "SHA256:abc", Err: cause}, ErrIdentity, ErrKeysRefused},
		{&HostKeyError{Changed: true, Err: ErrHostKeyChanged}, ErrHostKey, ErrUpstreamHostKey},
		{&HostKeyError{Declined: true, Err: ErrHostKeyUnknown}, ErrHostKey, ErrIdentity},
	} {
		wrapped := fmt.Errorf("attempt 1: %w", tc.err)
		require.ErrorIs(t, wrapped, tc.sentinel, tc.err.Error())
		require.NotErrorIs(t, wrapped, tc.other, tc.err.Error())
		require.NotEmpty(t, tc.err.Error())
	}
}

func TestErrorsUnwrapTheirCause(t *testing.T) {
	cause := errors.New("cause")

	require.ErrorIs(t, &IdentityError{List: true, Err: cause}, cause)
	require.ErrorIs(t, &HostKeyError{Err: ErrHostKeyChanged}, ErrHostKeyChanged)
	require.NotErrorIs(t, &HostKeyError{Err: ErrHostKeyChanged}, ErrHostKeyUnknown)

	var deadline *DeadlineError
	require.ErrorAs(t, fmt.Errorf("first join: %w", &DeadlineError{Why: Unreachable, Err: cause}), &deadline)
	require.Equal(t, Unreachable, deadline.Why)
	require.ErrorIs(t, deadline, cause)
}
