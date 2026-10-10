// Package join is the core of a guest joining an upterm session: it parses the
// target a guest names, joins the session over the connection to the relay
// that the embedder's Config.Dial opens, TCP for ssh or a WebSocket for ws and
// wss, and rejoins the session after the connection drops. It renders no text
// of its own; it returns typed errors and outcomes, and the command that
// embeds it decides what to tell the user.
//
// The core has to build for js/wasm as well as for the command line, so its
// imports are limited to what that target can link. These are the packages of
// this module it is meant to import, besides the standard library and
// golang.org/x/crypto/ssh:
//
//   - attach
//   - io (the module's own, not the standard library's)
//   - internal/termsize
//   - internal/liveness
//   - internal/logging
//   - internal/version
//   - upterm
//
// The list is the intended set, which review keeps. The build that "make
// wasm-check" runs and CI enforces catches only an import that doesn't build
// for js/wasm, a package that needs cgo or a system call js/wasm lacks, say,
// and not every import outside the list:
//
//	GOOS=js GOARCH=wasm go build ./join ./attach
package join
