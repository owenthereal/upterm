package command

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/go-multierror"
	uptermctx "github.com/owenthereal/upterm/internal/context"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/spf13/cobra"
)

// failureCodeAnnotation is the annotation a command declares its own
// "upterm failed" exit status in (D2a).
const failureCodeAnnotation = "upterm/failure-code"

// installSignalPolicy is InstallSignalPolicy; a var so a test can see Main
// call it.
var installSignalPolicy = InstallSignalPolicy

// mainRoot is the command tree Main runs; a var so a test can see what runs
// after the signal policy.
var mainRoot = cliRoot

// Main is the whole of main: the signal policy, the command, the exit status.
//
// The signal policy comes first and belongs to this process, not only to the
// daemon's Host.Run: the foreground host and attach hold the terminal here,
// and need SIGPIPE protection and the job-control dispositions before any of
// it is touched.
func Main() int {
	installSignalPolicy()
	cmd, err := mainRoot().ExecuteC()
	return Exit(cmd, err, os.Stderr)
}

// cliRoot is Root as Main runs it. cobra adds its completion command inside
// ExecuteC, too late for Root to make it runnable like the other groups, so
// it is added here first, and ExecuteC finds it there. Root itself goes
// without: cmd/gendoc writes a man page for every command Root has.
func cliRoot() *cobra.Command {
	root := Root()
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		if c.Name() == "completion" {
			reportUnknownCommands(c)
		}
	}
	return root
}

// Reported marks a diagnostic the command already printed (D1 case 3): Exit
// prints nothing more. Its status is the ExitCodeError it wraps, if any, or
// the command's failure code.
type Reported struct {
	Err error
}

func (e Reported) Error() string {
	return e.Err.Error()
}

func (e Reported) Unwrap() error {
	return e.Err
}

// SilentError is Reported's former name, kept for the call sites that use it.
type SilentError = Reported

// Exit prints err as D1 says and returns the process's exit status. cmd is
// what Root().ExecuteC returned (the failing command, or the root).
//
// The root silences cobra, so this is the one place an error is printed, in
// one of three ways:
//  1. An error with a message: one line per error, "upterm: <error>", on
//     stderr, and the same at error level in the command's log when it has
//     one, since upterm.log is where a failure is looked for later. Never the
//     usage: a usage error is that one line too.
//  2. An ExitCodeError with no message: nothing. The status is the whole
//     outcome — `session current -o` outside a session, `session wait`'s
//     status, the session status host, attach and join exit with — and
//     "upterm: exit status 4" would break a shell prompt that relies on the
//     silence.
//  3. Reported: nothing more; the command has said what happened.
//
// The status is the ExitCodeError's, when there is one, and otherwise the
// command's own failure code.
func Exit(cmd *cobra.Command, err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}

	var ec ExitCodeError
	hasCode := errors.As(err, &ec)
	statusOnly := hasCode && ec.Err == nil
	var reported Reported
	if !statusOnly && !errors.As(err, &reported) {
		report(cmd, err, stderr)
	}

	if hasCode {
		return ec.Code
	}
	return failureCode(cmd)
}

// report is D1's case 1: each of err's messages as a line on stderr, and in
// the command's log.
func report(cmd *cobra.Command, err error, stderr io.Writer) {
	var logger *logging.Logger
	if cmd != nil && cmd.Context() != nil {
		logger = uptermctx.Logger(cmd.Context())
	}
	for _, line := range errorLines(err) {
		_, _ = fmt.Fprintf(stderr, "upterm: %s\n", line)
		if logger != nil {
			logger.Error("command failed", "command", cmd.CommandPath(), "error", line)
		}
	}
}

// errorLines is err as the messages Exit prints, one per error. Each error a
// *multierror.Error collects is a message of its own, after whatever its
// wrappers say before the list, never multierror's "N errors occurred" list.
// A message with newlines of its own, such as host's warning for a changed
// relay key, stays one message: the prefix goes on its first line only.
func errorLines(err error) []string {
	var merr *multierror.Error
	if !errors.As(err, &merr) || len(merr.Errors) == 0 {
		return []string{err.Error()}
	}
	prefix := ""
	if p, ok := strings.CutSuffix(err.Error(), merr.Error()); ok {
		prefix = p
	}
	var lines []string
	for _, e := range merr.Errors {
		for _, line := range errorLines(e) {
			lines = append(lines, prefix+line)
		}
	}
	return lines
}

// failureCode is the command's own "upterm failed" status (D2a): the
// "upterm/failure-code" annotation, or 1.
func failureCode(cmd *cobra.Command) int {
	if cmd != nil {
		if code, err := strconv.Atoi(cmd.Annotations[failureCodeAnnotation]); err == nil {
			return code
		}
	}
	return 1
}

// unknownCommandError is what root and groups return for an unknown first
// argument, with cobra's suggestions (SuggestionsMinimumDistance 2) on the
// same line: "unknown command "x" for upterm session; did you mean list, set
// or wait?" rather than cobra's "Did you mean this?" block.
func unknownCommandError(cmd *cobra.Command, arg string) error {
	msg := fmt.Sprintf("unknown command %q", arg)
	if cmd.HasParent() {
		msg += " for " + cmd.CommandPath()
	}
	if cmd.SuggestionsMinimumDistance <= 0 {
		cmd.SuggestionsMinimumDistance = 2
	}
	suggestions := cmd.SuggestionsFor(arg)
	if len(suggestions) > 0 {
		slices.Sort(suggestions)
		msg += "; did you mean " + orList(slices.Compact(suggestions)) + "?"
	}
	return errors.New(msg)
}

// orList joins words as "a", "a or b", "a, b or c".
func orList(words []string) string {
	last := len(words) - 1
	if last == 0 {
		return words[0]
	}
	return strings.Join(words[:last], ", ") + " or " + words[last]
}
