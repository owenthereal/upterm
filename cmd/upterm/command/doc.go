// Package command is the upterm command line.
//
// # Extension API
//
// A program that embeds upterm builds its command through these
// declarations, so that its commands, its flags on upterm host and its say
// in how a run is hosted join upterm's own:
//
//   - [Root] and [RootWith];
//   - [Main] and [MainWith];
//   - [Extension], [HostFlag] and [Prepared];
//   - [Handoff], [HostSettings] and [HostOptions], with [FlagValue],
//     [FlagSource] and its values, [AuthorizedKeyFile] and [UserRef];
//   - [WriteConfigValue];
//   - [Logger].
//
// An extension's Prepare decides, in the process upterm host runs in, whether
// a run is delegated. A delegated run's session process is started with a
// [Handoff], in its environment, which other processes of the same user can
// read: it carries no credential, and an extension's [Prepared.Payload] must
// carry none either.
//
// This API may change in any minor release, and each change is listed in the
// release notes.
package command
