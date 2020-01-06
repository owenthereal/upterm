package rollbar

import (
	"fmt"
	"io"
	"log"
	"os"
)

const (
	// DefaultBuffer is the default size of the buffered channel used
	// for queueing items to send to Rollbar in the asynchronous
	// implementation of Transport.
	DefaultBuffer = 1000
	// DefaultRetryAttempts is the number of times we attempt to retry sending an item when
	// encountering temporary network errors
	DefaultRetryAttempts = 3
)

// Transport represents an object used for communicating with the Rollbar API.
type Transport interface {
	io.Closer
	// Send the body to the API, returning an error if the send fails. If the implementation to
	// asynchronous, then a failure can still occur when this method returns no error. In that case
	// this error represents a failure (or not) of enqueuing the payload.
	Send(body map[string]interface{}) error
	// Wait blocks until all messages currently waiting to be processed have been sent.
	Wait()
	// Set the access token to use for sending items with this transport.
	SetToken(token string)
	// Set the endpoint to send items to.
	SetEndpoint(endpoint string)
	// Set the logger to use instead of the standard log.Printf
	SetLogger(logger ClientLogger)
	// Set the number of times to retry sending an item if temporary http errors occurs before
	// failing.
	SetRetryAttempts(retryAttempts int)
	// Set whether to print the payload to the set logger or to stderr upon failing to send.
	SetPrintPayloadOnError(printPayloadOnError bool)
}

// ClientLogger is the interface used by the rollbar Client/Transport to report problems.
type ClientLogger interface {
	Printf(format string, args ...interface{})
}

// SilentClientLogger is a type that implements the ClientLogger interface but produces no output.
type SilentClientLogger struct{}

// Printf implements the ClientLogger interface.
func (s *SilentClientLogger) Printf(format string, args ...interface{}) {}

// NewTransport creates a transport that sends items to the Rollbar API asynchronously.
func NewTransport(token, endpoint string) Transport {
	return NewAsyncTransport(token, endpoint, DefaultBuffer)
}

// -- rollbarError

func rollbarError(logger ClientLogger, format string, args ...interface{}) {
	format = "Rollbar error: " + format + "\n"
	if logger != nil {
		logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func writePayloadToStderr(logger ClientLogger, payload map[string]interface{}) {
	format := "Rollbar item failed to send: %v\n"
	if logger != nil {
		logger.Printf(format, payload)
	} else {
		fmt.Fprintf(os.Stderr, format, payload)
	}
}
