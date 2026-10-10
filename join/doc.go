// Package join is the core of a guest joining an upterm session: it parses the
// target a guest names, dials the relay over ssh, ws or wss, and rejoins the
// session after the connection drops. It renders no text of its own; it
// returns typed errors and outcomes, and the command that embeds it decides
// what to tell the user.
//
// The core has to build for js/wasm as well as for the command line, so its
// imports are limited to what that target can link. It may import only these
// packages of this module, the standard library and golang.org/x/crypto/ssh:
//
//   - attach
//   - io (the module's own, not the standard library's)
//   - internal/termsize
//   - internal/liveness
//   - internal/logging
//   - internal/version
//   - upterm
//
// Anything else, a package that needs cgo or a system call js/wasm lacks, say,
// would break the build that "make wasm-check" runs and CI enforces:
//
//	GOOS=js GOARCH=wasm go build ./join ./attach
package join
