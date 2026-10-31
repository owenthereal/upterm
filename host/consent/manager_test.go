package consent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

type answer struct {
	decision Decision
	err      error
}
type review struct {
	ctx    context.Context
	prompt Prompt
	answer chan answer
}
type fakePrompter struct {
	calls              chan review
	ignoreCancellation bool
}

func quietManager(p Prompter) *Manager {
	return NewManager(p, slog.New(slog.NewTextHandler(io.Discard, nil)))
}
func newPrompter() *fakePrompter { return &fakePrompter{calls: make(chan review, 1024)} }
func (p *fakePrompter) Prompt(ctx context.Context, prompt Prompt) (Decision, error) {
	r := review{ctx, prompt, make(chan answer, 1)}
	p.calls <- r
	if p.ignoreCancellation {
		a := <-r.answer
		return a.decision, a.err
	}
	select {
	case a := <-r.answer:
		return a.decision, a.err
	case <-ctx.Done():
		return Deny, ctx.Err()
	}
}
func check(m *Manager, ctx context.Context, op Operation, c ClientInfo, subjects ...string) <-chan answer {
	result := make(chan answer, 1)
	go func() { d, e := m.CheckPermission(ctx, op, c, subjects...); result <- answer{d, e} }()
	synctest.Wait()
	return result
}
func next(t *testing.T, p *fakePrompter) review {
	t.Helper()
	select {
	case r := <-p.calls:
		return r
	default:
		t.Fatal("expected a consent prompt")
		return review{}
	}
}
func reply(r review, d Decision) { r.answer <- answer{decision: d}; synctest.Wait() }
func allowed(t *testing.T, result <-chan answer, d Decision) {
	t.Helper()
	a := <-result
	require.NoError(t, a.err)
	require.Equal(t, d, a.decision)
}
func denied(t *testing.T, result <-chan answer, err error) {
	t.Helper()
	a := <-result
	require.Equal(t, Deny, a.decision)
	require.ErrorIs(t, a.err, err)
}

var guest = ClientInfo{Fingerprint: "guest-key", ConnectionID: "connection-1"}
var reconnect = ClientInfo{Fingerprint: "guest-key", ConnectionID: "connection-2"}

// Removing capability, connection or full tuple from the grant key must fail.
func TestConsentScopes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		subjects := []string{"a\x00:b", "c:d\x00"}
		result := check(m, context.Background(), OpRename, guest, subjects...)
		r := next(t, p)
		require.Equal(t, subjects, r.prompt.Subjects)
		require.Equal(t, OpRename, r.prompt.Operation)
		require.Equal(t, guest, r.prompt.Client)
		require.NotEmpty(t, r.prompt.ID)
		reply(r, AllowConnection)
		allowed(t, result, AllowConnection)
		// SFTP operations share the path grant, but other capabilities do not.
		for _, op := range []Operation{OpDownload, OpUpload, OpDelete, OpMkdir, OpRmdir, OpRename, OpSymlink, OpLink, OpSetstat} {
			allowed(t, check(m, context.Background(), op, guest, subjects...), AllowConnection)
		}
		require.Len(t, p.calls, 0) // Exactly one prompt for identical scope.
		result = check(m, context.Background(), OpExec, guest, subjects...)
		reply(next(t, p), Deny)
		otherCapabilityResult := <-result
		require.Equal(t, Deny, otherCapabilityResult.decision)
		require.ErrorIs(t, otherCapabilityResult.err, ErrDenied)
		for _, tuple := range [][]string{{"a\x00:b", "changed"}, {"a\x00", "b:c:d\x00"}, {"a\x00:b:c:d\x00"}, {"a\x00:b", "c:d\x00", ""}} {
			result = check(m, context.Background(), OpRename, guest, tuple...)
			reply(next(t, p), Deny)
			denied(t, result, ErrDenied)
		}
		result = check(m, context.Background(), OpRename, reconnect, subjects...)
		reply(next(t, p), Deny)
		denied(t, result, ErrDenied)
		result = check(m, context.Background(), OpExec, guest, "echo ok")
		reply(next(t, p), AllowGuest)
		allowed(t, result, AllowGuest)
		allowed(t, check(m, context.Background(), OpExec, reconnect, "different command"), AllowGuest)
		result = check(m, context.Background(), OpDownload, reconnect, "different path")
		reply(next(t, p), Deny)
		denied(t, result, ErrDenied)
	})
}

// Expiry must win over a late prompt answer and may never reset at re-entry.
func TestConsentDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		p.ignoreCancellation = true
		m := quietManager(p)
		defer m.Close()
		arrival := time.Now()
		result := check(m, context.Background(), OpExec, guest, "sleep")
		r := next(t, p)
		require.Equal(t, arrival.Add(60*time.Second), r.prompt.Deadline)
		time.Sleep(60 * time.Second)
		synctest.Wait()
		denied(t, result, ErrTimeout)
		reply(r, AllowGuest)
		require.Zero(t, len(m.guests)+len(m.grants))
		result = check(m, context.Background(), OpExec, reconnect, "sleep")
		r = next(t, p)
		reply(r, Deny)
		denied(t, result, ErrDenied)
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		result = check(m, ctx, OpForward, guest, "127.0.0.1", "22")
		r = next(t, p)
		require.Equal(t, time.Now().Add(7*time.Second), r.prompt.Deadline)
		time.Sleep(7 * time.Second)
		synctest.Wait()
		reply(r, AllowConnection)
		denied(t, result, ErrTimeout)
		require.Zero(t, len(m.guests)+len(m.grants))
	})
}

// A plain answer cannot be adopted by a different connection on the same flight.
func TestConsentCoalescing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		first := check(m, context.Background(), OpExec, guest, "command")
		r := next(t, p)
		same := check(m, context.Background(), OpExec, guest, "command")
		time.Sleep(20 * time.Second)
		other := check(m, context.Background(), OpExec, reconnect, "command")
		require.Len(t, p.calls, 0)
		reply(r, AllowConnection)
		allowed(t, first, AllowConnection)
		allowed(t, same, AllowConnection)
		r2 := next(t, p)
		require.NotEqual(t, r.prompt.ID, r2.prompt.ID)
		require.Equal(t, reconnect, r2.prompt.Client)
		require.Equal(t, r.prompt.Deadline.Add(20*time.Second), r2.prompt.Deadline)
		reply(r2, Deny)
		denied(t, other, ErrDenied)
		require.Len(t, p.calls, 0)
		// Denial can resolve both connections on an identical flight.
		first = check(m, context.Background(), OpExec, guest, "denied")
		r = next(t, p)
		other = check(m, context.Background(), OpExec, reconnect, "denied")
		reply(r, Deny)
		denied(t, first, ErrDenied)
		denied(t, other, ErrDenied)
		require.Len(t, p.calls, 0)
	})
}

// A guest grant resolves all live tuples of that capability, across connections.
func TestConsentGuestGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		first := check(m, context.Background(), OpExec, guest, "one")
		r := next(t, p)
		other := check(m, context.Background(), OpExec, reconnect, "two")
		r2 := next(t, p)
		forward := check(m, context.Background(), OpForward, reconnect, "127.0.0.1", "22")
		r3 := next(t, p)
		reply(r, AllowGuest)
		allowed(t, first, AllowGuest)
		allowed(t, other, AllowGuest)
		require.ErrorIs(t, r2.ctx.Err(), context.Canceled)
		select {
		case <-forward:
			t.Fatal("guest exec grant crossed capability")
		default:
		}
		reply(r3, Deny)
		denied(t, forward, ErrDenied)
		stranger := ClientInfo{Fingerprint: "other-key", ConnectionID: "connection-3"}
		pending := check(m, context.Background(), OpExec, stranger, "one")
		reply(next(t, p), Deny)
		denied(t, pending, ErrDenied)
	})
}

// Empty identities may only obtain connection-scoped authority.
func TestConsentEmptyIdentity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		a := ClientInfo{ConnectionID: "a"}
		b := ClientInfo{ConnectionID: "b"}
		first := check(m, context.Background(), OpExec, a, "one")
		r := next(t, p)
		second := check(m, context.Background(), OpExec, b, "one")
		r2 := next(t, p)
		reply(r, AllowGuest)
		allowed(t, first, AllowConnection)
		select {
		case <-second:
			t.Fatal("empty identity crossed connections")
		default:
		}
		reply(r2, Deny)
		denied(t, second, ErrDenied)
		first = check(m, context.Background(), OpExec, a, "two")
		reply(next(t, p), Deny)
		denied(t, first, ErrDenied)
	})
}

// Cancellation of the displayed origin invalidates its ID before any answer.
func TestConsentOriginCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		p.ignoreCancellation = true
		m := quietManager(p)
		defer m.Close()
		ctx, cancel := context.WithCancel(context.Background())
		origin := check(m, ctx, OpExec, guest, "same")
		old := next(t, p)
		time.Sleep(10 * time.Second)
		survivor := check(m, context.Background(), OpExec, reconnect, "same")
		unrelated := check(m, context.Background(), OpForward, guest, "127.0.0.1", "22")
		separate := next(t, p)
		cancel()
		synctest.Wait()
		denied(t, origin, ErrCanceled)
		fresh := next(t, p)
		require.NotEqual(t, old.prompt.ID, fresh.prompt.ID)
		require.Equal(t, old.prompt.Deadline.Add(10*time.Second), fresh.prompt.Deadline)
		reply(old, AllowGuest)
		grantsFromStaleAnswer := len(m.guests) + len(m.grants)
		survivorResolvedByStaleAnswer := len(survivor)
		unrelatedResolvedByCancellation := len(unrelated)
		// Release even deliberately cancellation-ignoring prompt workers before
		// asserting, so assertion failures cannot leak test goroutines.
		reply(fresh, AllowConnection)
		reply(separate, Deny)
		require.Zero(t, grantsFromStaleAnswer)
		require.Zero(t, survivorResolvedByStaleAnswer)
		require.Zero(t, unrelatedResolvedByCancellation)
		allowed(t, survivor, AllowConnection)
		denied(t, unrelated, ErrDenied)
	})
}

func TestConsentWaiterDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		first := check(m, context.Background(), OpExec, guest, "one")
		old := next(t, p)
		time.Sleep(40 * time.Second)
		second := check(m, context.Background(), OpExec, reconnect, "one")
		time.Sleep(20 * time.Second)
		synctest.Wait()
		denied(t, first, ErrTimeout)
		fresh := next(t, p)
		require.NotEqual(t, old.prompt.ID, fresh.prompt.ID)
		require.Equal(t, time.Now().Add(40*time.Second), fresh.prompt.Deadline)
		time.Sleep(40 * time.Second)
		synctest.Wait()
		denied(t, second, ErrTimeout)
	})
}

func TestConsentClearConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		first := check(m, context.Background(), OpDownload, guest, "path")
		reply(next(t, p), AllowConnection)
		allowed(t, first, AllowConnection)
		second := check(m, context.Background(), OpDownload, reconnect, "path")
		reply(next(t, p), AllowConnection)
		allowed(t, second, AllowConnection)
		pending := check(m, context.Background(), OpExec, guest, "one")
		old := next(t, p)
		other := check(m, context.Background(), OpExec, reconnect, "one")
		m.ClearConnection(guest.ConnectionID)
		synctest.Wait()
		denied(t, pending, ErrCanceled)
		require.ErrorIs(t, old.ctx.Err(), context.Canceled)
		fresh := next(t, p)
		reply(fresh, Deny)
		denied(t, other, ErrDenied)
		allowed(t, check(m, context.Background(), OpDownload, reconnect, "path"), AllowConnection)
		first = check(m, context.Background(), OpDownload, guest, "path")
		reply(next(t, p), Deny)
		denied(t, first, ErrDenied)
		// Guest grants survive connection teardown.
		first = check(m, context.Background(), OpExec, guest, "grant")
		reply(next(t, p), AllowGuest)
		allowed(t, first, AllowGuest)
		m.ClearConnection(guest.ConnectionID)
		allowed(t, check(m, context.Background(), OpExec, reconnect, "another"), AllowGuest)
	})
}

func TestConsentClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		first := check(m, context.Background(), OpExec, guest, "grant")
		reply(next(t, p), AllowGuest)
		allowed(t, first, AllowGuest)
		pending := check(m, context.Background(), OpDownload, guest, "pending")
		r := next(t, p)
		m.Close()
		synctest.Wait()
		denied(t, pending, ErrUnavailable)
		require.ErrorIs(t, r.ctx.Err(), context.Canceled)
		require.Empty(t, m.guests)
		require.Empty(t, m.grants)
		denied(t, check(m, context.Background(), OpExec, guest, "grant"), ErrUnavailable)
		m.Close()
	})
}

// Removing any admission bound must cause an observable extra prompt/waiter.
func TestConsentBounds(t *testing.T) {
	cases := []struct {
		name    string
		count   int
		client  func(int) ClientInfo
		subject func(int) string
	}{
		{"distinct_flights", 32, func(i int) ClientInfo { return ClientInfo{Fingerprint: "g", ConnectionID: fmt.Sprint(i)} }, func(i int) string { return fmt.Sprint(i) }},
		{"per_connection", 32, func(int) ClientInfo { return guest }, func(i int) string { return "same" }},
		{"shared_flight", 64, func(i int) ClientInfo { return ClientInfo{Fingerprint: "g", ConnectionID: fmt.Sprint(i)} }, func(int) string { return "same" }},
		{"total_waiters", 256, func(i int) ClientInfo { return ClientInfo{Fingerprint: "g", ConnectionID: fmt.Sprint(i)} }, func(i int) string { return fmt.Sprint(i / 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newPrompter()
				m := quietManager(p)
				defer m.Close()
				for i := 0; i < tc.count; i++ {
					check(m, context.Background(), OpExec, tc.client(i), tc.subject(i))
				}
				result := check(m, context.Background(), OpExec, tc.client(tc.count), tc.subject(tc.count))
				denied(t, result, ErrOverloaded)
			})
		})
	}
}

func TestConsentValidation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		denied(t, check(m, context.Background(), Operation("bogus"), guest, "x"), ErrDenied)
		denied(t, check(quietManager(nil), context.Background(), OpExec, guest, "x"), ErrUnavailable)
		result := check(m, context.Background(), OpExec, guest, "x")
		reply(next(t, p), Decision(255))
		denied(t, result, ErrDenied)
		result = check(m, context.Background(), OpExec, guest, "x")
		r := next(t, p)
		r.answer <- answer{AllowGuest, errors.New("offline")}
		synctest.Wait()
		denied(t, result, ErrUnavailable)
		denied(t, check(m, context.Background(), OpRename, guest, strings.Repeat("é", 2048), strings.Repeat("x", 4097)), ErrSubjectTooLarge)
		require.Len(t, p.calls, 0)
		result = check(m, context.Background(), OpRename, guest, strings.Repeat("é", 2048), strings.Repeat("x", 4096))
		r = next(t, p)
		require.Equal(t, 8192, len(r.prompt.Subjects[0])+len(r.prompt.Subjects[1]))
		reply(r, AllowGuest)
		allowed(t, result, AllowGuest)
		// Cached grants do not require presentation and can cover larger subjects.
		allowed(t, check(m, context.Background(), OpDownload, reconnect, strings.Repeat("x", 9000)), AllowGuest)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		denied(t, check(m, ctx, OpDownload, reconnect, "cached"), ErrCanceled)
	})
}

// Every policy outcome must be diagnosable; logging cannot hold the state lock.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *lockedLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.buf.String() }
func consentOutcomes(t *testing.T, logs, requestID string) []string {
	t.Helper()
	var outcomes []string
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "consent decision" && record["request_id"] == strconv.QuoteToASCII(requestID) {
			outcomes = append(outcomes, record["outcome"].(string))
		}
	}
	return outcomes
}

func TestConsentLogging(t *testing.T) {
	t.Run("outcomes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var output lockedLog
			p := newPrompter()
			p.ignoreCancellation = true
			m := NewManager(p, slog.New(slog.NewJSONHandler(&output, nil)))
			defer m.Close()
			for _, err := range []error{ErrUnavailable, ErrDenied, ErrTimeout, ErrCanceled, ErrOverloaded, ErrSubjectTooLarge, ErrStale} {
				result := check(m, context.Background(), OpExec, guest, err.Error())
				r := next(t, p)
				r.answer <- answer{Deny, err}
				synctest.Wait()
				denied(t, result, err)
			}
			logs := output.String()
			for _, outcome := range []string{"unavailable", "denied", "timeout", "canceled", "overloaded", "subject_too_large", "stale"} {
				require.Contains(t, logs, `"outcome":"`+outcome+`"`)
			}
			for _, field := range []string{"capability", "operation", "subjects", "fingerprint", "connection_id", "request_id"} {
				require.Contains(t, logs, `"`+field+`"`)
			}
		})
	})
	// A request that times out or is canceled is recorded once, by its waiter.
	// Its prompt then returning because of that is no answer; only an answer
	// the prompter gives for the ended request is a late one.
	timeout := func(context.CancelFunc) { time.Sleep(PermissionTimeout) }
	cancellation := func(cancel context.CancelFunc) { cancel() }
	for _, tc := range []struct {
		name string
		end  func(context.CancelFunc)
		late *answer // nil: the prompt returns on its own cancellation
		want []string
	}{
		{"timeout", timeout, nil, []string{"timeout"}},
		{"cancellation", cancellation, nil, []string{"canceled"}},
		{"allow after timeout", timeout, &answer{AllowGuest, nil}, []string{"timeout", "stale"}},
		{"deny after cancellation", cancellation, &answer{Deny, nil}, []string{"canceled", "stale"}},
		{"stale answer after cancellation", cancellation, &answer{Deny, ErrStale}, []string{"canceled", "stale"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var output lockedLog
				p := newPrompter()
				p.ignoreCancellation = tc.late != nil
				m := NewManager(p, slog.New(slog.NewJSONHandler(&output, nil)))
				defer m.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				result := check(m, ctx, OpExec, guest, "ended")
				r := next(t, p)
				tc.end(cancel)
				synctest.Wait()
				<-result
				if tc.late != nil {
					r.answer <- *tc.late
				}
				synctest.Wait()
				require.Equal(t, tc.want, consentOutcomes(t, output.String(), r.prompt.ID))
				require.Empty(t, m.guests)
				require.Empty(t, m.grants)
			})
		})
	}
}

// An unrelated waiter cancellation cannot retire the displayed origin.
func TestConsentWaiterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		m := quietManager(p)
		defer m.Close()
		first := check(m, context.Background(), OpExec, guest, "same")
		r := next(t, p)
		ctx, cancel := context.WithCancel(context.Background())
		second := check(m, ctx, OpExec, reconnect, "same")
		cancel()
		synctest.Wait()
		denied(t, second, ErrCanceled)
		require.NoError(t, r.ctx.Err())
		require.Len(t, p.calls, 0)
		reply(r, AllowConnection)
		allowed(t, first, AllowConnection)
	})
}

// A prompt may return an allow immediately after it observes cancellation.
// Both context cancellation and expiry must prevent creating any grant.
type prompterFunc func(context.Context, Prompt) (Decision, error)

func (f prompterFunc) Prompt(ctx context.Context, p Prompt) (Decision, error) { return f(ctx, p) }
func TestConsentAnswerCancellationRace(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(fmt.Sprint(expire), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				p := prompterFunc(func(context.Context, Prompt) (Decision, error) {
					if expire {
						time.Sleep(60 * time.Second)
					} else {
						cancel()
					}
					return AllowGuest, nil
				})
				m := quietManager(p)
				defer m.Close()
				result := check(m, ctx, OpExec, guest, "race")
				if expire {
					denied(t, result, ErrTimeout)
				} else {
					denied(t, result, ErrCanceled)
				}
				require.Empty(t, m.guests)
				require.Empty(t, m.grants)
			})
		})
	}
}

// Close must join canceled prompt workers before it returns, even if they need
// time to finish after receiving cancellation.
func TestConsentCloseJoinsWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newPrompter()
		p.ignoreCancellation = true
		m := quietManager(p)
		pending := check(m, context.Background(), OpExec, guest, "pending")
		r := next(t, p)
		closed := make(chan struct{})
		go func() { m.Close(); close(closed) }()
		synctest.Wait()
		denied(t, pending, ErrUnavailable)
		returnedBeforeWorker := false
		select {
		case <-closed:
			returnedBeforeWorker = true
		default:
		}
		reply(r, AllowGuest)
		<-closed
		require.False(t, returnedBeforeWorker, "Close returned before its prompt worker exited")
		require.Empty(t, m.guests)
		require.Empty(t, m.grants)
	})
}

// A canceled prompt can observe cancellation immediately but need bounded time
// to release presentation resources. Retiring waiters must not free its worker
// reservation before that cleanup exits.
type cleaningReview struct {
	ctx      context.Context
	prompt   Prompt
	canceled chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (r *cleaningReview) finishCleanup() { r.once.Do(func() { close(r.release) }) }

type cleaningPrompter struct {
	mu         sync.Mutex
	calls      chan *cleaningReview
	reviews    []*cleaningReview
	live, peak int
}

func newCleaningPrompter() *cleaningPrompter {
	return &cleaningPrompter{calls: make(chan *cleaningReview, 1024)}
}
func (p *cleaningPrompter) Prompt(ctx context.Context, prompt Prompt) (Decision, error) {
	r := &cleaningReview{ctx: ctx, prompt: prompt, canceled: make(chan struct{}), release: make(chan struct{})}
	p.mu.Lock()
	p.live++
	p.peak = max(p.peak, p.live)
	p.reviews = append(p.reviews, r)
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.live--; p.mu.Unlock() }()
	p.calls <- r
	<-ctx.Done()
	close(r.canceled)
	<-r.release
	return Deny, ctx.Err()
}
func (p *cleaningPrompter) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.live, p.peak
}
func (p *cleaningPrompter) releaseAll() {
	p.mu.Lock()
	reviews := append([]*cleaningReview(nil), p.reviews...)
	p.mu.Unlock()
	for _, r := range reviews {
		r.finishCleanup()
	}
}
func nextCleaning(t *testing.T, p *cleaningPrompter) *cleaningReview {
	t.Helper()
	select {
	case r := <-p.calls:
		return r
	default:
		t.Fatal("expected a consent prompt")
		return nil
	}
}

func TestConsentWorkerBounds(t *testing.T) {
	t.Run("admission_churn", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newCleaningPrompter()
			m := quietManager(p)
			defer func() { p.releaseAll(); m.Close() }()
			var first *cleaningReview
			for i := 0; i < 32; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				pending := check(m, ctx, OpExec, guest, fmt.Sprint(i))
				r := nextCleaning(t, p)
				if first == nil {
					first = r
				}
				cancel()
				synctest.Wait()
				denied(t, pending, ErrCanceled)
				select {
				case <-r.canceled:
				default:
					t.Fatal("prompter did not observe cancellation")
				}
			}
			live, peak := p.counts()
			require.Equal(t, 32, live)
			require.Equal(t, 32, peak)
			for i := 0; i < 8; i++ {
				overflow := check(m, context.Background(), OpExec, guest, "overflow")
				_, peak = p.counts()
				require.LessOrEqual(t, peak, 32, "canceled cleanup must retain prompt capacity")
				denied(t, overflow, ErrOverloaded)
			}
			require.Len(t, p.calls, 0)
			first.finishCleanup()
			synctest.Wait()
			live, _ = p.counts()
			require.Equal(t, 31, live)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pending := check(m, ctx, OpExec, guest, "capacity reused")
			nextCleaning(t, p)
			live, peak = p.counts()
			require.Equal(t, 32, live)
			require.Equal(t, 32, peak)
			cancel()
			synctest.Wait()
			denied(t, pending, ErrCanceled)
		})
	})
	t.Run("replacement_churn", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			p := newCleaningPrompter()
			m := quietManager(p)
			defer func() { p.releaseAll(); m.Close() }()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pending := check(m, ctx, OpExec, guest, "same")
			current := nextCleaning(t, p)
			first := current
			for i := 1; i < 32; i++ {
				time.Sleep(time.Second)
				nextCtx, nextCancel := context.WithCancel(context.Background())
				defer nextCancel()
				survivor := check(m, nextCtx, OpExec, reconnect, "same")
				originalDeadline := time.Now().Add(60 * time.Second)
				cancel()
				synctest.Wait()
				denied(t, pending, ErrCanceled)
				fresh := nextCleaning(t, p)
				require.NotEqual(t, current.prompt.ID, fresh.prompt.ID)
				require.Equal(t, originalDeadline, fresh.prompt.Deadline)
				current, pending, cancel = fresh, survivor, nextCancel
			}
			time.Sleep(time.Second)
			survivorCtx, survivorCancel := context.WithCancel(context.Background())
			defer survivorCancel()
			survivor := check(m, survivorCtx, OpExec, guest, "same")
			cancel()
			synctest.Wait()
			denied(t, pending, ErrCanceled)
			live, peak := p.counts()
			require.LessOrEqual(t, peak, 32, "replacement prompts must reserve worker capacity")
			require.Equal(t, 32, live)
			denied(t, survivor, ErrOverloaded)
			require.Len(t, p.calls, 0)
			first.finishCleanup()
			synctest.Wait()
			deadline := time.Now().Add(9 * time.Second)
			retryCtx, retryCancel := context.WithDeadline(context.Background(), deadline)
			defer retryCancel()
			retry := check(m, retryCtx, OpExec, guest, "same")
			fresh := nextCleaning(t, p)
			require.NotEqual(t, current.prompt.ID, fresh.prompt.ID)
			require.Equal(t, deadline, fresh.prompt.Deadline)
			live, peak = p.counts()
			require.Equal(t, 32, live)
			require.Equal(t, 32, peak)
			retryCancel()
			synctest.Wait()
			denied(t, retry, ErrCanceled)
		})
	})
}

func TestConsentLoggingBounded(t *testing.T) {
	var output bytes.Buffer
	m := NewManager(nil, slog.New(slog.NewJSONHandler(&output, nil)))
	subjects := make([]string, 1000)
	for i := range subjects {
		subjects[i] = "path\x1b[2J\n" + strings.Repeat("x", 10000)
	}
	m.log(OpUpload, ClientInfo{Fingerprint: "key\x1b[0m", ConnectionID: strings.Repeat("c", 10000)}, subjects, "request", Deny, errors.New(strings.Repeat("failure\n", 10000)))
	require.Less(t, output.Len(), 20000)
	var fields map[string]any
	require.NoError(t, json.Unmarshal(output.Bytes(), &fields))
	for _, key := range []string{"fingerprint", "connection_id", "error"} {
		value := fields[key].(string)
		require.NotContains(t, value, "\x1b")
		require.NotContains(t, value, "\n")
		require.Less(t, len(value), 2000)
	}
	for _, subject := range fields["subjects"].([]any) {
		require.NotContains(t, subject.(string), "\x1b")
		require.NotContains(t, subject.(string), "\n")
		require.Less(t, len(subject.(string)), 2000)
	}
}
