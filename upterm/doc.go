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
//     registration it holds for a routing ID;
//   - [GateAdmitRequestType], which asserts to a delegated registration's
//     home that its authority admitted the hop's guest;
//   - [GateHeldRequestType], which asks that home whether it still holds the
//     registration;
//   - [ServerDelegatedControlRequestType], a host's report on its own
//     delegated registration;
//   - [HostDelegatedDecisionRequestType], a decision about a host's
//     delegated session.
//
// This API may change in any minor release, and each change is listed in the
// release notes.
package upterm
