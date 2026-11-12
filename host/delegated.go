package host

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/owenthereal/upterm/host/api"
	"github.com/owenthereal/upterm/host/internal"
	"github.com/owenthereal/upterm/host/sessiondir"
	"github.com/owenthereal/upterm/internal/registration"
	"github.com/owenthereal/upterm/internal/termtext"
	"github.com/owenthereal/upterm/server"
	"golang.org/x/crypto/ssh"
)

// Broker places a delegated run: it tells the authority that decides the
// session about the run, and answers with where and how the run registers.
type Broker interface {
	// Place runs once per run, after the name is claimed and before anything is
	// dialled.
	Place(ctx context.Context, run Run) (Placement, error)
}

// Run is what a Broker is told about the run it places. None of it is a
// secret.
type Run struct {
	// RunKey is the key the run registers with and proves, and RoutingID the
	// session ID that key and the run's own secret derive.
	RunKey    ssh.PublicKey
	RoutingID string
	// Name is the local session name the run claimed, and NameGenerated says
	// upterm drew it rather than being given it.
	Name          string
	NameGenerated bool
	// Command, ForceCommand and LoginCommand are the host's, each empty when
	// unset.
	Command      []string
	ForceCommand []string
	LoginCommand []string
	// Capabilities is what guests may ask the relay for, as the session
	// reports what they may do: "shell" always, "exec" unless execution is
	// off, "sftp" unless file transfers are off, and "direct-tcpip" unless
	// forwarding is off.
	Capabilities []string
}

// Placement is where and how a Broker placed a run. It carries no
// credential: the Broker keeps whatever it used to place the run to itself.
type Placement struct {
	// RoutingID must be the run's.
	RoutingID string
	// Relay is the host:port the run registers with.
	Relay string
	// Trust is the only relay keys the run trusts there.
	Trust InitialTrust
	// Refresh must be nil: a run whose placement needs its relay keys
	// refreshed ends before anything is dialled.
	Refresh TrustSource
	// Protocol and ExternalID are what the registration asks the relay's
	// authority for: the delegated protocol, 1 to 64 printable ASCII bytes
	// with no whitespace, and the external session, a canonical UUID.
	Protocol   string
	ExternalID string
	// GuestAddress is the SSH user guests reach the session as, printed into
	// the commands people paste: 1 to 255 letters, digits, '.', '_', '+' or
	// '-', starting with a letter or digit.
	GuestAddress string
	// Association and Display are what the session record shows about the
	// delegation. Association's fields are identifiers, recorded as given or
	// refused, never made safe: the service is an https URL of at most 2048
	// bytes, with a host name and no userinfo; the account and the login are
	// 1 to 256 bytes each; all three are UTF-8 with no control character, a
	// line feed included; and the superseded session ID is empty or a
	// canonical UUID.
	// Display's name is at most 64 bytes; it has at most 8 links, each with a
	// label of at most 64 bytes and an https URL of at most 2048 bytes, and
	// at most 16 notes of at most 256 bytes each, all measured once their
	// text is made safe for a terminal. The name, the labels and the notes
	// are one line each: a line feed in them is replaced.
	Association sessiondir.DelegationAssociation
	Display     sessiondir.DelegationDisplay
	// Published, if set, is called once, on Run's goroutine, when Run is
	// through recording the delegation: after the record holds it, or once
	// Run has failed to put it there or refused the placement, and before
	// anything is dialled. A Broker that holds other runs off until they can
	// see this one lets them go here.
	Published func()
}

// InitialTrust is the relay keys a placement lists, with their freshness.
type InitialTrust struct {
	// Keys are 1 to 16 plain SSH public keys, in their canonical wire
	// encoding.
	Keys [][]byte
	// Sequence is the sequence of the key set they came from, 0 when the
	// service didn't say, and SentAt when the request that returned them was
	// sent.
	Sequence uint64
	SentAt   time.Time
}

// TrustSource refreshes a run's relay keys. It carries no credential either.
type TrustSource interface {
	Refresh(ctx context.Context, nonce []byte) (keys [][]byte, sequence uint64, echoed []byte, err error)
	// Interval is how often the host refreshes, and Lifetime how long a
	// refresh's keys are trusted, from when its request was sent.
	Interval() time.Duration
	Lifetime() time.Duration
}

// NameTakenError is a Broker's answer that the run's name is taken where the
// run was placed. Text is the Broker's, for the operator.
type NameTakenError struct{ Text string }

func (e *NameTakenError) Error() string { return e.Text }

func (e *NameTakenError) Unwrap() error { return ErrNameTaken }

// ErrNameTaken is what a *NameTakenError unwraps to.
var ErrNameTaken = errors.New("the session name is taken where the run was placed")

// Decision is what the authority decided about a delegated session after its
// command started.
type Decision int

const (
	// DecisionStopped is the authority stopping the session: its command is
	// being terminated.
	DecisionStopped Decision = iota + 1
	// DecisionWithdrawn is the authority withdrawing the session's remote
	// access: guests can't reach it through the relay any more, and its
	// command goes on running locally.
	DecisionWithdrawn
)

const (
	// delegatedReportTimeout bounds one report's wait for the relay's
	// answer, which waits on the authority's.
	delegatedReportTimeout = 10 * time.Second
	// delegatedReportRetry is how long a ready report the relay could not
	// take waits before it is sent again.
	delegatedReportRetry = time.Second
	// finalReportBudget is how long the exit report waits for its
	// acknowledgment, from when it is sent, before the registration is
	// closed under it and the exit is left unconfirmed. A shutdown's budget
	// for telemetry: it authorizes nothing.
	finalReportBudget = 5 * time.Second
)

// The bounds of a placement's fields.
const (
	maxAuthorityName = 64
	maxLinks         = 8
	maxLinkLabel     = 64
	maxLinkURL       = 2048
	maxNotes         = 16
	maxNote          = 256
	maxService       = 2048
	maxAccount       = 256
	maxLogin         = 256
)

var (
	// errInvalidPlacement is a placement that isn't this run's, or isn't
	// well formed.
	errInvalidPlacement = errors.New("the placement for this run is invalid")
	// errRefreshUnsupported is a placement whose relay keys need refreshing.
	errRefreshUnsupported = errors.New("this upterm can't refresh relay keys, and the placement for this run needs that")
)

// guestAddressRe is what a placement's guest address must be: the SSH user
// of the ssh command guests paste, which then needs no quoting and can't be
// read as an option.
var guestAddressRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$`)

// delegatedMode is a delegated run as Run keeps it: its placement, display
// sanitized, the relay it registers with, the only keys it trusts there, and
// every decision the relay has made about it, ordered across all its
// registrations.
type delegatedMode struct {
	placement Placement
	// authority is how texts name the session's authority.
	authority string
	relay     *url.URL
	pins      internal.RelayPins
	decisions *internal.DelegatedDecisions

	// launchMu guards launch, which settles once whether the command was let
	// start or a final decision came first: launchUnsettled until one of the
	// two takes it, and then whichever did, for good.
	launchMu sync.Mutex
	launch   launchState
}

// launchState is whether a delegated run's command was let start or a final
// decision came before it, once one of the two is settled.
type launchState int

const (
	launchUnsettled launchState = iota
	launchLet
	launchDecided
)

// mayLaunch settles that the command starts, and reports true, unless a final
// decision is already in force or has settled it first. Once it has reported
// true, every decision is one about a running session.
func (m *delegatedMode) mayLaunch() bool {
	m.launchMu.Lock()
	defer m.launchMu.Unlock()
	if m.launch == launchUnsettled {
		m.launch = launchLet
		if m.final() != server.DelegatedDisposition_DELEGATED_UNSPECIFIED {
			m.launch = launchDecided
		}
	}
	return m.launch == launchLet
}

// launched reports whether the command was let start before this final
// decision, and if nothing had settled it yet, settles that the decision
// came first: the command then never starts.
func (m *delegatedMode) launched() bool {
	m.launchMu.Lock()
	defer m.launchMu.Unlock()
	if m.launch == launchUnsettled {
		m.launch = launchDecided
	}
	return m.launch == launchLet
}

// capabilitiesFor is what guests of a run with permissions p may ask the
// relay for, as the session reports what they may do.
func capabilitiesFor(p internal.Permissions) []string {
	var report api.GetSessionResponse
	p.Report(&report)
	capabilities := []string{"shell"}
	if report.GetExecution() != "off" {
		capabilities = append(capabilities, "exec")
	}
	if report.GetFileTransfer() != internal.FileTransferOff {
		capabilities = append(capabilities, "sftp")
	}
	if report.GetTcpForwarding() != "off" {
		capabilities = append(capabilities, "direct-tcpip")
	}
	return capabilities
}

// startDelegated has the Broker place the run of hostKey and secret, checks
// that the placement is this run's and well formed, and records the
// delegation before anything is dialled, then tells the Broker it is through.
func (c *Host) startDelegated(ctx context.Context, hostKey ssh.Signer, secret []byte, permissions internal.Permissions) (*delegatedMode, error) {
	name := c.Name
	if c.SessionDir != nil {
		name = c.SessionDir.Name()
	}
	run := Run{
		RunKey:        hostKey.PublicKey(),
		RoutingID:     registration.ID(hostKey.PublicKey(), secret),
		Name:          name,
		NameGenerated: c.NameGenerated,
		Command:       c.Command,
		ForceCommand:  c.ForceCommand,
		LoginCommand:  c.LoginCommand,
		Capabilities:  capabilitiesFor(permissions),
	}
	p, err := c.Broker.Place(ctx, run)
	if err != nil {
		return nil, err
	}
	if p.Published != nil {
		defer p.Published()
	}
	p.Display = sanitizedDisplay(p.Display)
	relay, pins, err := checkPlacement(run, p)
	if err != nil {
		return nil, err
	}
	if p.Refresh != nil {
		return nil, errRefreshUnsupported
	}
	if c.SessionDir != nil {
		// Fatal, as the ready write is: a delegated session no local reader
		// can find the delegation of is one nothing can tell is still
		// running.
		if err := c.SessionDir.Update(func(r *sessiondir.Record) {
			r.Delegation = &sessiondir.Delegation{
				DelegationAssociation: p.Association,
				DelegationDisplay:     p.Display,
				ExternalSessionID:     p.ExternalID,
				RoutingID:             p.RoutingID,
				Relay:                 p.Relay,
				GuestAddress:          p.GuestAddress,
			}
		}); err != nil {
			return nil, fmt.Errorf("failed to record the session's delegation: %w", err)
		}
	}
	return &delegatedMode{
		placement: p,
		authority: internal.AuthorityName(p.Display.Authority),
		relay:     relay,
		pins:      pins,
		decisions: &internal.DelegatedDecisions{},
	}, nil
}

// sanitizedDisplay is d with every string in it made safe for a terminal,
// and no nil list, so the record always has its lists. The authority's name,
// each link's label and each note are one line each: a line feed in them is
// replaced as every other control character is, since they are printed inside
// lines of upterm's own, where a line of their own could pass for upterm's.
func sanitizedDisplay(d sessiondir.DelegationDisplay) sessiondir.DelegationDisplay {
	clean := func(s string) string { return string(termtext.Sanitize([]byte(s), false)) }
	line := func(s string) string { return strings.ReplaceAll(clean(s), "\n", "�") }
	out := sessiondir.DelegationDisplay{
		Authority: line(d.Authority),
		Links:     make([]sessiondir.DelegationLink, 0, len(d.Links)),
		Notes:     make([]string, 0, len(d.Notes)),
	}
	for _, l := range d.Links {
		out.Links = append(out.Links, sessiondir.DelegationLink{Label: line(l.Label), URL: clean(l.URL)})
	}
	for _, n := range d.Notes {
		out.Notes = append(out.Notes, line(n))
	}
	return out
}

// checkPlacement checks that p is run's and well formed, in order, and
// returns the relay to dial and the keys to trust there. The error names the
// first check that failed.
func checkPlacement(run Run, p Placement) (*url.URL, internal.RelayPins, error) {
	invalid := func(reason string) (*url.URL, internal.RelayPins, error) {
		return nil, internal.RelayPins{}, fmt.Errorf("%w: %s", errInvalidPlacement, reason)
	}
	if p.RoutingID != run.RoutingID {
		return invalid("the routing ID is not this run's")
	}
	if !internal.ValidDelegatedProtocol(p.Protocol) {
		return invalid("the protocol is not 1 to 64 printable ASCII bytes with no whitespace")
	}
	if !internal.ValidUUID(p.ExternalID) {
		return invalid("the external session ID is not a canonical UUID")
	}
	if !validRelayAddress(p.Relay) {
		return invalid("the relay address is not a valid host:port")
	}
	pins, err := internal.ParseRelayPins(p.Trust.Keys)
	if err != nil {
		return invalid("the relay keys are not 1 to 16 distinct canonical plain SSH public keys")
	}
	if !guestAddressRe.MatchString(p.GuestAddress) {
		return invalid("the guest address is not 1 to 255 letters, digits, '.', '_', '+' or '-', starting with a letter or digit")
	}
	if reason := associationProblem(p.Association); reason != "" {
		return invalid(reason)
	}
	if reason := displayProblem(p.Display); reason != "" {
		return invalid(reason)
	}
	return &url.URL{Scheme: "ssh", Host: p.Relay}, pins, nil
}

// associationProblem is why a can't be recorded, or "" when it can. Its
// fields are identifiers, so one that isn't well formed is refused, never
// made safe.
func associationProblem(a sessiondir.DelegationAssociation) string {
	// No userinfo: a placement carries no credential, and a password is one.
	if u, err := url.Parse(a.Service); len(a.Service) > maxService || !controlFree(a.Service) || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "the service is not an https URL of at most 2048 bytes, with no userinfo or control characters"
	}
	if len(a.Account) < 1 || len(a.Account) > maxAccount || !controlFree(a.Account) {
		return "the account is not 1 to 256 bytes of UTF-8 with no control characters"
	}
	if len(a.Login) < 1 || len(a.Login) > maxLogin || !controlFree(a.Login) {
		return "the login is not 1 to 256 bytes of UTF-8 with no control characters"
	}
	if a.SupersededSessionID != "" && !internal.ValidUUID(a.SupersededSessionID) {
		return "the superseded session ID is not a canonical UUID"
	}
	return ""
}

// controlFree reports whether s is UTF-8 with no control character in it, a
// line feed included.
func controlFree(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// displayProblem is why d, already sanitized, can't be shown, or "" when it
// can.
func displayProblem(d sessiondir.DelegationDisplay) string {
	if len(d.Authority) > maxAuthorityName {
		return "the authority's name is longer than 64 bytes"
	}
	if len(d.Links) > maxLinks {
		return "there are more than 8 links"
	}
	for _, l := range d.Links {
		if len(l.Label) > maxLinkLabel {
			return "a link's label is longer than 64 bytes"
		}
		if u, err := url.Parse(l.URL); len(l.URL) > maxLinkURL || err != nil || u.Scheme != "https" || u.Host == "" {
			return "a link's URL is not an https URL of at most 2048 bytes"
		}
	}
	if len(d.Notes) > maxNotes {
		return "there are more than 16 notes"
	}
	for _, n := range d.Notes {
		if len(n) > maxNote {
			return "a note is longer than 256 bytes"
		}
	}
	return ""
}

// validRelayAddress reports whether s is a host:port to dial, written as it
// is meant: an IP literal without a zone, in its canonical form, or a
// lowercase DNS name of letters, digits and inner hyphens, and a decimal port
// from 1 to 65535 with no leading zero.
func validRelayAddress(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
		return false
	}
	if !canonicalHost(host) {
		return false
	}
	return net.JoinHostPort(host, port) == s
}

// canonicalHost reports whether host is an IP literal without a zone, in its
// canonical form, or a lowercase DNS name of letters, digits and inner
// hyphens whose last label isn't all digits, which would be a misspelled
// address.
func canonicalHost(host string) bool {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == "" && addr.String() == host
	}
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// tunnel makes t a registration of this delegated session: delegated, ordered
// with the run's other registrations, and trusting only the pins, recorded in
// authority. A nil delegatedMode, a local run's, leaves t as it is.
func (m *delegatedMode) tunnel(t *internal.ReverseTunnel, authority *internal.RelayAuthority) {
	if m == nil {
		return
	}
	t.Delegated = &server.DelegatedSession{Protocol: m.placement.Protocol, ExternalSessionId: m.placement.ExternalID}
	t.Decisions = m.decisions
	t.HostKeyCallback = authority.PinnedTo(m.pins, m.placement.Display.Authority)
	t.ProxyURL = nil
}

// address is the SSH user guests reach the session as: its guest address,
// or for a local run, whatever the relay registered.
func (m *delegatedMode) address(registered string) string {
	if m == nil {
		return registered
	}
	return m.placement.GuestAddress
}

// recordDecision records that the authority decided d about the running
// session, one of sessiondir's decisions. Not fatal: the session acts on the
// decision whether or not the record says so.
func (c *Host) recordDecision(m *delegatedMode, d string, logger *slog.Logger) {
	if c.SessionDir == nil {
		return
	}
	if err := c.SessionDir.Update(func(r *sessiondir.Record) {
		if r.Delegation != nil {
			// A copy, so that no earlier copy of the record changes under
			// whoever holds it.
			delegation := *r.Delegation
			delegation.Decision = d
			r.Delegation = &delegation
		}
	}); err != nil {
		logger.Warn("failed to record what "+m.authority+" decided about the session", "decision", d, "error", err)
	}
}

// final is the stopped or withdrawn decision in force, or
// DELEGATED_UNSPECIFIED while there is none, as there never is for a local
// run.
func (m *delegatedMode) final() server.DelegatedDisposition {
	if m == nil {
		return server.DelegatedDisposition_DELEGATED_UNSPECIFIED
	}
	switch d, _ := m.decisions.Current(); d {
	case server.DelegatedDisposition_DELEGATED_STOPPED, server.DelegatedDisposition_DELEGATED_WITHDRAWN:
		return d
	}
	return server.DelegatedDisposition_DELEGATED_UNSPECIFIED
}

// beforeLaunch is the error that ends a run whose final decision, d, came
// before its command started, which then never does.
func (m *delegatedMode) beforeLaunch(d server.DelegatedDisposition) error {
	if d == server.DelegatedDisposition_DELEGATED_STOPPED {
		return errors.New(m.authority + " stopped the session before its command started; no command was launched")
	}
	return errors.New(m.authority + " withdrew the session before its command started; no command was launched")
}

// stopped and withdrawn are why the guest door of a session the authority
// stopped or withdrew serves nobody any more.
func (m *delegatedMode) stopped() error { return errors.New(m.authority + " stopped the session") }

func (m *delegatedMode) withdrawn() error {
	return errors.New(m.authority + " withdrew the session's remote access")
}

// reporter is a registration that can report to the relay.
type reporter interface {
	Report(ctx context.Context, event internal.DelegatedEvent) error
}

// finalReporter is a registration the exit is reported on, and then closed.
type finalReporter interface {
	reporter
	Close()
}

// report sends event on t, bounded by delegatedReportTimeout.
func report(ctx context.Context, t tunnel, event internal.DelegatedEvent) error {
	r, ok := t.(reporter)
	if !ok {
		return errors.New("no delegated registration to report on")
	}
	ctx, cancel := context.WithTimeout(ctx, delegatedReportTimeout)
	defer cancel()
	return r.Report(ctx, event)
}

// reportReady tells the authority the session is ready, on whichever
// registration is current, until the relay acknowledges it, refuses it
// outright, or the authority decides the session's end, or ctx ends. A report
// the relay could not take is sent again, identically on the same
// registration, after delegatedReportRetry; one it hasn't answered yet is
// waited on again rather than sent again, so a registration has one ready
// report outstanding at most.
func (m *delegatedMode) reportReady(ctx context.Context, current func() tunnel, logger *slog.Logger) {
	for failed := false; m.final() == server.DelegatedDisposition_DELEGATED_UNSPECIFIED; failed = true {
		err := report(ctx, current(), internal.DelegatedEvent{})
		if err == nil || ctx.Err() != nil {
			return
		}
		if !retryableReport(err) {
			logger.Error(m.authority+" refused the report that this session is ready", "error", err)
			return
		}
		// Said once: through an outage, every retry fails the same way.
		if !failed {
			logger.Warn(m.authority+" has not acknowledged that this session is ready; reporting it again until it does", "error", err, "wait", delegatedReportRetry)
		} else {
			logger.Debug(m.authority+" has still not acknowledged that this session is ready", "error", err)
		}
		timer := time.NewTimer(delegatedReportRetry)
		select {
		case <-ctx.Done():
		case <-m.decisions.Terminal():
		case <-timer.C:
		}
		timer.Stop()
	}
}

// retryableReport is a report error that another report may get past: the
// authority unavailable, a registration since replaced, or no answer. A
// refusal as invalid or unsupported, and an answer outside the protocol, are
// final.
func retryableReport(err error) bool {
	var refused *server.DelegatedRefusedError
	if errors.As(err, &refused) {
		return refused.Retryable() || refused.Code == server.DelegatedErrorCode_DELEGATED_STALE_GENERATION
	}
	return !errors.Is(err, internal.ErrDelegatedRelayUnsupported)
}

// reportExit tells the authority the command's own outcome, res, on t, and
// closes t, unless the authority withdrew the session, which is then no
// business of the authority's.
func (m *delegatedMode) reportExit(t tunnel, res internal.CommandResult, logger *slog.Logger) {
	if d, _ := m.decisions.Current(); d == server.DelegatedDisposition_DELEGATED_WITHDRAWN {
		return
	}
	r, ok := t.(finalReporter)
	if !ok {
		return
	}
	if err := reportFinal(r, exitEvent(res)); err != nil {
		logger.Warn(m.authority+" did not confirm the command's exit", "error", err)
	}
}

// reportFinal reports event on r, waits finalReportBudget at most for the
// relay to acknowledge it, and closes r either way. The budget is its own,
// independent of whatever context the session ended with.
func reportFinal(r finalReporter, event internal.DelegatedEvent) error {
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), finalReportBudget)
	defer cancel()
	return r.Report(ctx, event)
}

// exitEvent is the exit report for a command's own outcome: its status when
// it exited with one a report can carry, and an unknown status otherwise.
func exitEvent(res internal.CommandResult) internal.DelegatedEvent {
	if res.Exited && res.Code >= math.MinInt32 && res.Code <= math.MaxInt32 {
		return internal.DelegatedEvent{Exit: true, ExitStatus: int32(res.Code), StatusKnown: true}
	}
	return internal.DelegatedEvent{Exit: true}
}
