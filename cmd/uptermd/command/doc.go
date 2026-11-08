// Package command is the uptermd command line.
//
// # Extension API
//
// A program that embeds uptermd builds its command through these
// declarations, so that its flags, subcommands and server extensions join
// uptermd's own:
//
//   - [Root] and [RootWith];
//   - [Extension];
//   - [Config], with its [Config.String] and [Config.Bool] methods;
//   - [ConfigFor].
//
// This API may change in any minor release, and each change is listed in the
// release notes.
package command
