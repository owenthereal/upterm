// Package ci reports a hosted terminal session to the CI system running it.
//
// A session hosted from a CI job has no one watching its terminal: the banner
// `upterm host` prints goes into a build log that may not be read until the
// job is over, and the person who wants to join is looking at the CI system's
// own UI. Reporting is therefore the CI system's job, done the way that system
// expects — a step output another step can consume, a job summary, an
// annotation — and each one of those is a different file or protocol per
// provider.
//
// Detect returns the provider this process is running under, or nil when it is
// not one this package knows how to report to. A nil Provider is not an error:
// the session still runs and still prints its banner, and everything here is
// addition on top of that.
package ci

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Session is what a CI system is told about a hosted session: enough to join
// it, and enough to tell two of them apart in a job that hosts more than one.
type Session struct {
	// SSHCommand is the command a client runs to join, e.g.
	// "ssh TOKEN@uptermd.upterm.dev". It is the whole point of the report.
	SSHCommand string

	// Name is the session's local name, as `upterm session info NAME` takes it.
	Name string
}

// Provider is a CI system that can be told about a session.
type Provider interface {
	// Name identifies the provider in upterm's own output.
	Name() string

	// Actor is the account that triggered the job, in the form the provider's
	// code host uses for a username, or "" when the provider does not say.
	// It is what --limit-access-to-actor authorizes.
	Actor() string

	// Workspace is the directory the job checked its repository out into, or
	// "" when the provider does not say.
	Workspace() string

	// Ready reports a session that is up and can be joined. It is called once,
	// from the session-created callback, before the hosted command starts.
	Ready(s Session) error
}

// ciEnvVars are the environment variables that identify a CI environment,
// whether or not this package can report to it. Detection is deliberately
// broader than reporting: a session's client IPs are hidden in any CI system,
// because the build log of any of them may be public.
var ciEnvVars = []string{
	"CI",                     // Generic CI indicator (GitHub Actions, GitLab CI, etc.)
	"GITHUB_ACTIONS",         // GitHub Actions
	"GITLAB_CI",              // GitLab CI
	"CIRCLECI",               // CircleCI
	"TRAVIS",                 // Travis CI
	"JENKINS_URL",            // Jenkins
	"BUILDKITE",              // Buildkite
	"TF_BUILD",               // Azure Pipelines
	"TEAMCITY_VERSION",       // TeamCity
	"BITBUCKET_BUILD_NUMBER", // Bitbucket Pipelines
}

// IsCI reports whether this process is running in a CI environment.
func IsCI() bool { return IsCIEnv(os.Getenv) }

// IsCIEnv is IsCI against an arbitrary environment, for tests.
func IsCIEnv(getenv func(string) string) bool {
	for _, v := range ciEnvVars {
		if getenv(v) != "" {
			return true
		}
	}
	return false
}

// Detect returns the CI provider this process is running under, or nil when
// there is none this package can report to.
func Detect() Provider { return DetectEnv(os.Getenv) }

// DetectEnv is Detect against an arbitrary environment, for tests.
func DetectEnv(getenv func(string) string) Provider {
	// GITHUB_ACTIONS rather than GITHUB_ACTOR or GITHUB_WORKSPACE: those two
	// are also set by act and by other runners that imitate the environment
	// without implementing the workflow-command files this writes to.
	if getenv("GITHUB_ACTIONS") == "true" {
		return &GitHubActions{getenv: getenv, stdout: os.Stdout}
	}
	return nil
}

// GitHubActions reports to GitHub Actions through the two files the runner
// watches (GITHUB_OUTPUT, GITHUB_STEP_SUMMARY) and the ::notice:: workflow
// command on stdout.
type GitHubActions struct {
	getenv func(string) string
	stdout io.Writer
}

func (g *GitHubActions) Name() string { return "GitHub Actions" }

func (g *GitHubActions) Actor() string { return g.getenv("GITHUB_ACTOR") }

func (g *GitHubActions) Workspace() string { return g.getenv("GITHUB_WORKSPACE") }

// Ready publishes the join command three ways, because each reaches a
// different reader: the step output is for another step in the same job, the
// job summary is for a human looking at the finished run (and for the REST
// API, which is how a session is retrieved from outside the job), and the
// annotation is for someone watching the run live.
//
// A failure to write any one of them is reported, but never stops the others:
// a session that is up and joinable must not be torn down because a log file
// was not writable.
func (g *GitHubActions) Ready(s Session) error {
	var errs []error

	if err := g.appendFile("GITHUB_OUTPUT", func() (string, error) {
		return keyValueFile("ssh-command", s.SSHCommand)
	}); err != nil {
		errs = append(errs, err)
	}

	if err := g.appendFile("GITHUB_STEP_SUMMARY", func() (string, error) {
		return summary(s), nil
	}); err != nil {
		errs = append(errs, err)
	}

	if _, err := io.WriteString(g.stdout, notice("Upterm session", s.SSHCommand)); err != nil {
		errs = append(errs, fmt.Errorf("writing the session annotation: %w", err))
	}

	return errors.Join(errs...)
}

// appendFile appends to one of the runner's workflow-command files.
//
// An unset variable is not an error: GITHUB_OUTPUT and GITHUB_STEP_SUMMARY are
// set by the runner for a step, and their absence means this is running under
// something that sets GITHUB_ACTIONS without being a step — `act`, a
// hand-rolled container, a test. Nothing is lost by staying quiet there, and
// failing would take the session down with it.
//
// The content is built inside the callback so that a value which cannot be
// encoded is reported without the file having been opened and truncated-open
// for an append that then never happens.
func (g *GitHubActions) appendFile(envVar string, content func() (string, error)) error {
	path := g.getenv(envVar)
	if path == "" {
		return nil
	}

	body, err := content()
	if err != nil {
		return fmt.Errorf("%s: %w", envVar, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening %s (%s): %w", envVar, path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(body); err != nil {
		return fmt.Errorf("writing %s (%s): %w", envVar, path, err)
	}

	return f.Close()
}

// keyValueFile renders one entry of the GITHUB_OUTPUT format.
//
// The heredoc form is used even though an SSH command is a single line,
// because the alternative — key=value — has no encoding at all for a value
// containing a newline, and the runner would read whatever followed as further
// entries. A hostname is not upterm's to trust: --server is a URL the caller
// supplies, and it reaches this string by way of the session's connect
// command.
func keyValueFile(key, value string) (string, error) {
	delim, err := randomDelimiter()
	if err != nil {
		return "", err
	}

	// A value containing the delimiter would end the entry early and leave the
	// rest to be parsed as more entries — the injection the delimiter exists to
	// prevent. 16 random bytes make this unreachable in practice; it is checked
	// because "unreachable in practice" is not a guarantee worth a silent
	// truncation of a value someone else supplied.
	if strings.Contains(value, delim) {
		return "", fmt.Errorf("value for %s contains its own delimiter", key)
	}

	return fmt.Sprintf("%s<<%s\n%s\n%s\n", key, delim, value, delim), nil
}

// randomDelimiter returns a heredoc delimiter in the shape GitHub's own
// toolkit uses.
func randomDelimiter() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating an output delimiter: %w", err)
	}
	return "ghadelimiter_" + hex.EncodeToString(b[:]), nil
}

// summary renders the job-summary entry. It is Markdown, and the join command
// is fenced so that the reader can copy it without the renderer having turned
// anything in it into a link.
func summary(s Session) string {
	var b strings.Builder
	b.WriteString("### Upterm session\n\n")
	if s.Name != "" {
		fmt.Fprintf(&b, "Session `%s` is waiting for a client.\n\n", s.Name)
	}
	b.WriteString("```\n")
	b.WriteString(s.SSHCommand)
	b.WriteString("\n```\n")
	return b.String()
}

// notice renders a ::notice:: workflow command.
func notice(title, message string) string {
	return fmt.Sprintf("::notice title=%s::%s\n", escapeProperty(title), escapeData(message))
}

// escapeData escapes the message of a workflow command. The runner parses
// these line by line, so a raw newline in a message would end the command and
// leave the remainder to be read as ordinary log output — or as another
// command.
func escapeData(s string) string {
	return strings.NewReplacer(
		"%", "%25",
		"\r", "%0D",
		"\n", "%0A",
	).Replace(s)
}

// escapeProperty escapes a workflow command's property value, which has two
// more delimiters than the message does.
func escapeProperty(s string) string {
	return strings.NewReplacer(
		"%", "%25",
		"\r", "%0D",
		"\n", "%0A",
		":", "%3A",
		",", "%2C",
	).Replace(s)
}
