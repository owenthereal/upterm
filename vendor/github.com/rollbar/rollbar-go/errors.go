package rollbar

import (
	"fmt"
)

// ErrHTTPError is an HTTP error status code as defined by
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
type ErrHTTPError int

// Error implements the error interface.
func (e ErrHTTPError) Error() string {
	return fmt.Sprintf("rollbar: service returned status: %d", e)
}

// ErrBufferFull is an error which is returned when the asynchronous transport is used and the
// channel used for buffering items for sending to Rollbar is full.
type ErrBufferFull struct{}

// Error implements the error interface.
func (e ErrBufferFull) Error() string {
	return "buffer full, dropping error on the floor"
}
