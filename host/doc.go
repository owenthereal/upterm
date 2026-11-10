// Package host runs an upterm session: it registers the session with a
// relay, keeps that registration up, and serves the hosted command to the
// guests the relay forwards and to the local terminal.
//
// # Extension API
//
// A program that embeds upterm has a session's registration, and its guests,
// decided by an authority outside the relay through these declarations:
//
//   - [Broker], which places a run, and [Host.Broker];
//   - [Run], what a Broker is told about the run it places;
//   - [Placement], where and how a Broker placed it;
//   - [InitialTrust], the relay keys a placement lists;
//   - [TrustSource], a source of refreshed relay keys, which this version
//     refuses a placement for;
//   - [NameTakenError] and [ErrNameTaken], a name taken where the run was
//     placed;
//   - [Decision], with [DecisionStopped] and [DecisionWithdrawn], and
//     [Host.DecisionCallback];
//   - [Host.NameGenerated].
//
// Neither a Placement nor a TrustSource carries a credential: whatever a
// Broker used to place the run stays with the Broker, and nothing of it is
// kept in the running session.
//
// This API may change in any minor release, and each change is listed in the
// release notes.
package host
