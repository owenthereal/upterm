// Package upterm is what upterm's host, guests and relay share on the wire:
// SSH versions, request types and their payloads, environment variables and
// the relay's guest-facing texts.
//
// # Extension API
//
// A program that embeds uptermd or upterm speaks to the relay with these
// declarations:
//
//   - [GateModeRequestType], which asks the node a hop reached which
//     registration it holds for a routing ID.
//
// This API may change in any minor release, and each change is listed in the
// release notes.
package upterm
