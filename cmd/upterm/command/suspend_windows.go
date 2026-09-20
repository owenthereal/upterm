//go:build windows

package command

import "errors"

// suspendSupported is false: Windows has no job control to hand the terminal
// back to, so ~^Z is not offered and ^Z reaches the session as a keystroke.
const suspendSupported = false

// suspendAvailable is false for the same reason; it exists so the hook site
// reads the same on every platform.
func suspendAvailable() bool { return false }

func stopSelf() error { return errors.ErrUnsupported }
