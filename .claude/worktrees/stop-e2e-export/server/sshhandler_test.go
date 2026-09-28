package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SSHHandlerTestSuite struct {
	suite.Suite
}

func TestSSHHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(SSHHandlerTestSuite))
}

func (s *SSHHandlerTestSuite) TestIsExpectedShutdownError() {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			name:     "io.EOF",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "connection closed",
			err:      errors.New("connection closed"),
			expected: true,
		},
		{
			name:     "use of closed network connection",
			err:      errors.New("use of closed network connection"),
			expected: true,
		},
		{
			name:     "connection reset by peer",
			err:      errors.New("read tcp 127.0.0.1:8080->127.0.0.1:8081: connection reset by peer"),
			expected: true,
		},
		{
			name:     "broken pipe",
			err:      errors.New("write tcp 127.0.0.1:8080->127.0.0.1:8081: broken pipe"),
			expected: true,
		},
		{
			name:     "generic network error with connection reset",
			err:      &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")},
			expected: true,
		},
		{
			name:     "unexpected error",
			err:      errors.New("unexpected database error"),
			expected: false,
		},
		{
			name:     "authentication failure",
			err:      errors.New("ssh: handshake failed: authentication failed"),
			expected: false,
		},
		{
			name:     "permission denied",
			err:      errors.New("permission denied"),
			expected: false,
		},
	}

	for _, tt := range tests {
		s.Run(tt.name, func() {
			result := isExpectedShutdownError(tt.err)
			assert.Equal(s.T(), tt.expected, result,
				"isExpectedShutdownError(%v) should return %v", tt.err, tt.expected)
		})
	}
}

func (s *SSHHandlerTestSuite) TestIsExpectedShutdownError_EdgeCases() {
	// Test error with "closed" in middle of message
	err := errors.New("the connection was closed unexpectedly")
	assert.True(s.T(), isExpectedShutdownError(err),
		"Expected 'closed' substring to be detected as shutdown error")

	// Test multiple shutdown indicators
	err = errors.New("broken pipe: connection closed")
	assert.True(s.T(), isExpectedShutdownError(err),
		"Expected multiple shutdown indicators to be detected")

	// Test partial matches that will trigger (which is fine for "closed")
	err = errors.New("unclosed parenthesis")
	assert.True(s.T(), isExpectedShutdownError(err),
		"'unclosed' contains 'closed' substring and should match")

	// Test empty error message
	err = errors.New("")
	assert.False(s.T(), isExpectedShutdownError(err),
		"Empty error message should not be expected shutdown error")
}

func (s *SSHHandlerTestSuite) TestIsExpectedShutdownError_WrappedErrors() {
	// Test wrapped context.Canceled
	wrappedCanceled := errors.New("operation failed: context canceled")
	assert.False(s.T(), isExpectedShutdownError(wrappedCanceled),
		"String-wrapped context canceled should not match errors.Is check")

	// Test actual wrapped context.Canceled using fmt.Errorf
	actualWrapped := fmt.Errorf("operation failed: %w", context.Canceled)
	assert.True(s.T(), isExpectedShutdownError(actualWrapped),
		"Properly wrapped context.Canceled should be detected")

	// Test wrapped io.EOF
	wrappedEOF := fmt.Errorf("read operation failed: %w", io.EOF)
	assert.True(s.T(), isExpectedShutdownError(wrappedEOF),
		"Properly wrapped io.EOF should be detected")
}
