package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
)

// ErrSessionNotFound represents a non-retryable session not found error
type ErrSessionNotFound struct {
	SessionID string
}

func (e *ErrSessionNotFound) Error() string {
	return fmt.Sprintf("session %s not found", e.SessionID)
}

var (
	// ErrSuperseded refuses a registration that doesn't supersede the one the
	// store holds for its ID.
	ErrSuperseded = errors.New("superseded by a newer registration")
	// ErrLeaseLost is the definite answer that a registration no longer holds
	// its entry, as opposed to a renewal that merely failed.
	ErrLeaseLost = errors.New("session lease lost")
)

const (
	DefaultSessionTTL    = 30 * time.Minute       // Default TTL for session data in Consul
	DefaultConsulTimeout = 5 * time.Second        // Default timeout for Consul operations
	DefaultWatchTimeout  = 10 * time.Minute       // Default timeout for Consul watch operations (long-polling)
	DefaultMaxRetries    = 3                      // Default number of retries for Consul operations
	DefaultRetryDelay    = 100 * time.Millisecond // Default delay between retries
	DefaultKeyPrefix     = "uptermd"              // Default key prefix for Consul storage
	UnusedNodeAddress    = "localhost"            // Placeholder address for node registration (not used but required by Consul)
)

// Session represents the complete session information
type Session struct {
	ID       string
	NodeAddr string
	// Generation orders registrations of the same ID. 0 is a legacy
	// registration: a random ID with no proof behind it.
	Generation           uint64
	HostUser             string
	HostPublicKeys       []ssh.PublicKey
	ClientAuthorizedKeys []ssh.PublicKey
}

// MarshalJSON implements custom JSON marshaling for Session
func (s *Session) MarshalJSON() ([]byte, error) {
	// Generation is omitted when zero, so a legacy entry reads exactly as it
	// did before generations existed.
	type sessionJSON struct {
		ID                   string
		NodeAddr             string
		Generation           uint64 `json:",omitempty"`
		HostUser             string
		HostPublicKeys       [][]byte
		ClientAuthorizedKeys [][]byte
	}

	var hostKeys [][]byte
	for _, key := range s.HostPublicKeys {
		hostKeys = append(hostKeys, ssh.MarshalAuthorizedKey(key))
	}

	var clientKeys [][]byte
	for _, key := range s.ClientAuthorizedKeys {
		clientKeys = append(clientKeys, ssh.MarshalAuthorizedKey(key))
	}

	return json.Marshal(sessionJSON{
		ID:                   s.ID,
		NodeAddr:             s.NodeAddr,
		Generation:           s.Generation,
		HostUser:             s.HostUser,
		HostPublicKeys:       hostKeys,
		ClientAuthorizedKeys: clientKeys,
	})
}

// UnmarshalJSON implements custom JSON unmarshaling for Session
func (s *Session) UnmarshalJSON(data []byte) error {
	type sessionJSON struct {
		ID                   string
		NodeAddr             string
		Generation           uint64 `json:",omitempty"`
		HostUser             string
		HostPublicKeys       [][]byte
		ClientAuthorizedKeys [][]byte
	}

	var temp sessionJSON
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	s.ID = temp.ID
	s.NodeAddr = temp.NodeAddr
	s.Generation = temp.Generation
	s.HostUser = temp.HostUser

	// Parse host public keys
	for _, keyBytes := range temp.HostPublicKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse host public key: %w", err)
		}
		s.HostPublicKeys = append(s.HostPublicKeys, key)
	}

	// Parse client authorized keys
	for _, keyBytes := range temp.ClientAuthorizedKeys {
		key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse client authorized key: %w", err)
		}
		s.ClientAuthorizedKeys = append(s.ClientAuthorizedKeys, key)
	}

	return nil
}

// IsClientKeyAllowed checks if a client key is authorized for this session
func (s *Session) IsClientKeyAllowed(key ssh.PublicKey) bool {
	if len(s.ClientAuthorizedKeys) == 0 {
		return true
	}

	for _, k := range s.ClientAuthorizedKeys {
		if utils.KeysEqual(k, key) {
			return true
		}
	}

	return false
}

// Registration is one stored claim to a session ID. Whatever later renews,
// releases or rebuilds the entry acts through the handle, so it can only touch
// its own claim, never a successor's.
type Registration struct {
	Session *Session
	// ConfirmedAt is the send time of the lock-session creation this
	// registration's lease came from (memory: taken before the write). The
	// expiry budget counts from it, and the lease's TTL clock can't have
	// started earlier, so the budget can only end early.
	ConfirmedAt time.Time
	lease       string // Consul lock session; "" in memory
	index       uint64 // Consul ModifyIndex as written; 0 in memory
	// epoch is the store cache's epoch when the Consul call that wrote index
	// began; 0 in memory. index orders against a watch delivery's only within
	// that epoch.
	epoch uint64
}

func (r *Registration) ID() string { return r.Session.ID }

func (r *Registration) Generation() uint64 { return r.Session.Generation }

// Capable reports whether the host proved its key, and so can reconnect. A
// legacy registration keeps today's behaviour.
func (r *Registration) Capable() bool { return r.Session.Generation > 0 }

// Same reports whether r and o are the same registration. A rebuild stores the
// same registration again under a new lease, and its handle stands in for the
// one it replaced, so this compares identity rather than handles.
func (r *Registration) Same(o *Registration) bool {
	return r != nil && o != nil && sameIdentity(r.Session, o.Session)
}

// sameIdentity reports whether a and b are the same registration. Only one
// connection can hold an (ID, generation, node): a proof is bound to its
// connection, another connection needs a higher generation, and a legacy ID is
// random.
func sameIdentity(a, b *Session) bool {
	return a.ID == b.ID && a.Generation == b.Generation && a.NodeAddr == b.NodeAddr
}

// mayRegister reports whether a fresh registration next may replace cur. Only
// a higher generation may: the same one again would be the same registration,
// which the first connection's cleanup ends, taking the second's with it.
func mayRegister(next, cur *Session) bool {
	return next.Generation > cur.Generation
}

// mayRebuild reports whether the owner's rebuild of next may replace cur. It
// may also replace next's own registration, which is what it stores again.
func mayRebuild(next, cur *Session) bool {
	return mayRegister(next, cur) || sameIdentity(next, cur)
}

func supersededError(next, cur *Session) error {
	return fmt.Errorf("session %s: generation %d on %s can't replace generation %d on %s: %w",
		next.ID, next.Generation, next.NodeAddr, cur.Generation, cur.NodeAddr, ErrSuperseded)
}

// SessionStore defines the interface for session storage.
//
// Registrations are ordered: a stored entry is replaced only by a higher
// generation, or by its owner rebuilding it, and a handle's Release and Renew
// act only on its own entry.
type SessionStore interface {
	// Register stores s when its ID is absent or s has a higher generation
	// than the stored entry. Otherwise it returns an error wrapping
	// ErrSuperseded and writes nothing. A Register that fails may outlast ctx
	// by up to DefaultConsulTimeout, while it destroys a lease it created.
	Register(ctx context.Context, s *Session) (*Registration, error)
	// Reregister is the owner's rebuild of reg after a known loss: it stores
	// reg's session again under a new lease, as Register does, and may also
	// replace an entry of reg's own identity, which Register refuses. It
	// orders, retries and cleans up as Register does.
	Reregister(ctx context.Context, reg *Registration) (*Registration, error)
	// Release removes reg's entry if reg still holds it.
	Release(ctx context.Context, reg *Registration) error
	// Renew keeps reg's entry alive. An error wrapping ErrLeaseLost means reg
	// no longer holds it; any other error leaves that unknown.
	Renew(ctx context.Context, reg *Registration) error
	// LeaseTTL is how long an unrenewed entry lasts; 0 if it doesn't expire.
	LeaseTTL() time.Duration
	// Get complete session data
	Get(sessionID string) (*Session, error)
	// GetFresh reads sessionID from the store itself, skipping any cache, and
	// updates the cache with what it finds, the entry or its absence, as Get's
	// read-through does. It gives up once ctx is done.
	GetFresh(ctx context.Context, sessionID string) (*Session, error)
	// Delete session data, only for an entry this instance holds
	Delete(sessionID string) error
	// BatchDelete multiple sessions efficiently, likewise
	BatchDelete(sessionIDs []string) error
	// List all sessions (for cleanup and management)
	List() ([]*Session, error)
	// Observe has fn called with each view of every entry the store's watch
	// delivers; see SessionManager.Observe. A store no other writer shares
	// has nothing to watch, and never calls fn.
	Observe(fn func(epoch, index uint64, entries map[string]*Session))
	// Close cleans up resources and stops background processes
	Close() error
}

// sessionCache provides thread-safe in-memory caching for sessions. Writes
// reach it out of order, from replies and from the watch, so each entry keeps
// the Consul ModifyIndex of the write it describes, and an earlier write never
// replaces a later one.
//
// Consul's index can go backwards: when the entry with the highest index is
// removed, after a snapshot restore, or across an upgrade. Indexes then order
// writes only within an epoch, which advances each time the watch's index
// drops.
type sessionCache struct {
	sessions map[string]cachedSession
	// watched is the index of the last watch snapshot applied. That snapshot
	// held every entry written at or before it that still stood, so one it
	// left out had been removed or superseded by then.
	watched uint64
	// epoch counts the drops in the watch's index.
	epoch  uint64
	mutex  sync.RWMutex
	logger *slog.Logger
}

// cachedSession is a session as the Consul write at index stored it, and the
// lock session that holds it.
type cachedSession struct {
	session *Session
	index   uint64
	lease   string
}

// newSessionCache creates a new session cache
func newSessionCache(logger *slog.Logger) *sessionCache {
	return &sessionCache{
		sessions: make(map[string]cachedSession),
		logger:   logger,
	}
}

// Get retrieves a session from cache
func (c *sessionCache) Get(sessionID string) (*Session, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.sessions[sessionID]
	return entry.session, exists
}

// Has checks if a session exists in cache without retrieving it (useful for testing)
func (c *sessionCache) Has(sessionID string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, exists := c.sessions[sessionID]
	return exists
}

// Epoch is the cache's current epoch. A local write captures it before its
// Consul call, and hands it to Set.
func (c *sessionCache) Epoch() uint64 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.epoch
}

// Set caches entry, a local write whose Consul call began in epoch. It is
// dropped if the epoch has changed since: its index doesn't order against
// those after the drop, and until the next watch delivery the read-through
// finds the entry instead. Within the epoch it is dropped if the cache
// already describes that write or a later one: a reply can arrive after the
// watch, or a later registration, has delivered something newer. With no entry
// cached, a write the last watch snapshot already covered is dropped too: that
// snapshot left it out, so it had been removed or superseded, and nothing else
// would correct it before the next delivery.
func (c *sessionCache) Set(sessionID string, entry cachedSession, epoch uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if epoch != c.epoch {
		return
	}
	if cur, ok := c.sessions[sessionID]; ok {
		if cur.index >= entry.index {
			return
		}
	} else if entry.index <= c.watched {
		return
	}
	c.sessions[sessionID] = entry
	c.logger.Debug("cached session", "session", sessionID)
}

// Delete removes sessionID's entry if lease holds it. Releasing a lease
// removes what that lease held, never an entry a rebuild or a later
// registration holds under another.
func (c *sessionCache) Delete(sessionID, lease string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if cur, ok := c.sessions[sessionID]; !ok || cur.lease != lease {
		return
	}
	delete(c.sessions, sessionID)
	c.logger.Debug("removed session from cache", "session", sessionID)
}

// Evict removes sessionID's entry, which a read of Consul at index, begun in
// epoch, found gone. It orders as Set does: across an epoch change the read's
// index means nothing, and an entry written after index is one the read didn't
// see, so either stays.
func (c *sessionCache) Evict(sessionID string, index, epoch uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if epoch != c.epoch {
		return
	}
	if cur, ok := c.sessions[sessionID]; !ok || cur.index > index {
		return
	}
	delete(c.sessions, sessionID)
	c.logger.Debug("evicted a session the store no longer has", "session", sessionID)
}

// ReplaceAll replaces the cache with snapshot, the watch's view of every
// session as of index, and takes ownership of snapshot. An entry a later write
// stored stays: the watch hasn't caught up with that write, and the snapshot
// that does will include it, or its removal. An index below the last
// snapshot's starts a new epoch: no index from before the drop orders against
// one after it, so the snapshot is then taken whole. It returns the epoch it
// applied the snapshot in.
func (c *sessionCache) ReplaceAll(index uint64, snapshot map[string]cachedSession) (epoch uint64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if index < c.watched {
		c.epoch++
	} else {
		for sessionID, cur := range c.sessions {
			if cur.index > index {
				snapshot[sessionID] = cur
			}
		}
	}

	// Calculate changes for logging
	var added, updated, deleted int
	for sessionID, next := range snapshot {
		if cur, exists := c.sessions[sessionID]; exists {
			if !reflect.DeepEqual(cur, next) {
				updated++
			}
		} else {
			added++
		}
	}

	// Count deleted sessions
	for sessionID := range c.sessions {
		if _, exists := snapshot[sessionID]; !exists {
			deleted++
		}
	}

	// Replace the entire session map atomically
	c.sessions = snapshot
	c.watched = index

	if added > 0 || updated > 0 || deleted > 0 {
		c.logger.Info("updated session cache", "total", len(snapshot), "added", added, "updated", updated, "deleted", deleted)
	}

	return c.epoch
}

// consulSessionStore implements SessionStore using Consul KV with hybrid read-through cache
type consulSessionStore struct {
	client    *api.Client
	logger    *slog.Logger
	ttl       time.Duration
	keyPrefix string
	// Hybrid cache for instant lookups with fallback to Consul
	cache *sessionCache
	// Watch management
	watchPlan *watch.Plan
	// held maps each session ID this instance registered to the lock sessions
	// it registered it under and hasn't released: one, or more while a late
	// reply or a rebuilt registration's old lease is outstanding. Delete and
	// BatchDelete act only through it, so neither can remove an entry another
	// node registered or took over. The leases aren't ordered, since Consul's
	// index can go backwards; each release drops only its own.
	held   map[string]map[string]struct{}
	heldMu sync.Mutex
	// observers are called with each watch delivery, on the watch's goroutine.
	observers   []func(epoch, index uint64, entries map[string]*Session)
	observersMu sync.Mutex
}

// heldLeases returns the lock sessions this instance holds sessionID under.
// The caller holds heldMu.
func (c *consulSessionStore) heldLeases(sessionID string) []string {
	return slices.Sorted(maps.Keys(c.held[sessionID]))
}

// newConsulSessionStore creates a new ConsulSessionStore
func newConsulSessionStore(consulURL *url.URL, ttl time.Duration, logger *slog.Logger) (*consulSessionStore, error) {
	config := api.DefaultConfig()
	config.Address = consulURL.Host
	config.Scheme = consulURL.Scheme
	config.HttpClient = &http.Client{
		Timeout: DefaultConsulTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		},
	}
	if u := consulURL.User; u != nil {
		config.Token, _ = u.Password()
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	var keyPrefix string
	if v := strings.TrimPrefix(consulURL.Path, "/"); v != "" {
		keyPrefix = v
	} else {
		keyPrefix = DefaultKeyPrefix
	}

	if ttl == 0 {
		ttl = DefaultSessionTTL
	}

	store := &consulSessionStore{
		client:    client,
		logger:    logger,
		ttl:       ttl,
		keyPrefix: keyPrefix,
		cache:     newSessionCache(logger),
		held:      make(map[string]map[string]struct{}),
	}

	// Register the node with Consul
	if err := store.registerNode(); err != nil {
		return nil, fmt.Errorf("failed to register node with consul: %w", err)
	}

	// Initialize session replication by starting the watch
	if err := store.startSessionWatch(config); err != nil {
		return nil, fmt.Errorf("failed to start session watch: %w", err)
	}

	return store, nil
}

// Register stores session as a fresh registration.
func (c *consulSessionStore) Register(ctx context.Context, session *Session) (*Registration, error) {
	return c.register(ctx, session, mayRegister)
}

// Reregister stores reg's session again, taking the entry over from reg's own
// lock session, or its earlier rebuild's, if one still holds it.
func (c *consulSessionStore) Reregister(ctx context.Context, reg *Registration) (*Registration, error) {
	return c.register(ctx, reg.Session, mayRebuild)
}

// register stores session under a lock session of its own, replacing a stored
// entry only where may allows. The generation check and the move of the lock
// are one transaction, conditional on the entry the decision was read from, so
// no other registration can land between them: whichever commits second finds
// the entry changed, and reads and decides again.
func (c *consulSessionStore) register(ctx context.Context, session *Session, may func(next, cur *Session) bool) (*Registration, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	if session.ID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Outside retry: deterministic operations
	kvStoreKey := c.SessionKey(session.ID)

	// Serialize session data as JSON first to fail fast on marshaling errors
	sessionData, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	wo := (&api.WriteOptions{}).WithContext(ctx)
	qo := (&api.QueryOptions{}).WithContext(ctx)

	// Before any Consul call, so a drop in the index the watch delivers while
	// the call runs keeps its reply out of the cache.
	epoch := c.cache.Epoch()

	var (
		lease   string
		created time.Time
		index   uint64
	)
	err = retry.Do(
		func() error {
			// One lock session for the call, however many attempts it takes.
			// Its TTL clock starts when Consul creates it, so the send time of
			// the create is the earliest the expiry budget can safely start.
			if lease == "" {
				sent := time.Now()
				id, _, err := c.client.Session().CreateNoChecks(c.createConsulLockSession(session.ID), wo)
				if err != nil {
					return fmt.Errorf("failed to create consul lock session: %w", err)
				}
				lease, created = id, sent
			}

			pair, _, err := c.client.KV().Get(kvStoreKey, qo)
			if err != nil {
				return fmt.Errorf("failed to read session data: %w", err)
			}

			// The lock session is this call's alone, so finding it on the entry
			// means an earlier attempt committed and only its reply was lost:
			// the entry is this registration's own write, not one to order it
			// against.
			if pair != nil && pair.Session == lease {
				index = pair.ModifyIndex
				return nil
			}

			var ops api.KVTxnOps
			if pair == nil {
				ops = api.KVTxnOps{
					{Verb: api.KVCheckNotExists, Key: kvStoreKey},
					{Verb: api.KVLock, Key: kvStoreKey, Value: sessionData, Session: lease},
				}
			} else {
				if cur := storedSession(pair.Value); !may(session, cur) {
					return retry.Unrecoverable(supersededError(session, cur))
				}
				ops = api.KVTxnOps{{Verb: api.KVCheckIndex, Key: kvStoreKey, Index: pair.ModifyIndex}}
				if pair.Session != "" {
					// Unlock writes its op's value too. Give it the new one, so
					// no step of the move stores anything else.
					ops = append(ops, &api.KVTxnOp{Verb: api.KVUnlock, Key: kvStoreKey, Value: sessionData, Session: pair.Session})
				}
				ops = append(ops, &api.KVTxnOp{Verb: api.KVLock, Key: kvStoreKey, Value: sessionData, Session: lease})
			}

			ok, resp, _, err := c.client.KV().Txn(ops, qo)
			if err != nil {
				return fmt.Errorf("failed to store session data: %w", err)
			}
			if !ok {
				return fmt.Errorf("session %s changed while registering: %s", session.ID, describeTxnErrors(resp.Errors))
			}
			// The lock is the last operation, so its result is the last one.
			if n := len(resp.Results); n > 0 {
				index = resp.Results[n-1].ModifyIndex
			}
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.Debug("retrying consul register operation",
				"operation", "register",
				"attempt", n+1,
				"error", err,
			)
		}),
	)

	if err != nil {
		if lease != "" {
			c.destroyUnusedLease(lease)
		}
		return nil, err
	}

	// Immediately update local cache for strong consistency. A reply can
	// arrive after a later registration of the ID has committed and been
	// recorded here, or delivered by the watch. Tracking this lease alongside
	// the later one is harmless, since its release drops only its own; the
	// cache takes it only where nothing later is, or guests would be routed to
	// a superseded registration.
	c.heldMu.Lock()
	if c.held[session.ID] == nil {
		c.held[session.ID] = make(map[string]struct{})
	}
	c.held[session.ID][lease] = struct{}{}
	c.cache.Set(session.ID, cachedSession{session: session, index: index, lease: lease}, epoch)
	c.heldMu.Unlock()

	c.logger.Debug("registered session in consul and cache",
		"session", session.ID,
		"node", session.NodeAddr,
		"generation", session.Generation,
		"key", kvStoreKey,
	)

	return &Registration{Session: session, ConfirmedAt: created, lease: lease, index: index, epoch: epoch}, nil
}

// storedSession ranks a stored value for ordering. One that doesn't parse
// ranks as generation 0 from no node: a proven registration may replace it,
// and a legacy one may not.
func storedSession(value []byte) *Session {
	var s Session
	if err := json.Unmarshal(value, &s); err != nil {
		return &Session{}
	}
	return &s
}

func describeTxnErrors(errs api.TxnErrors) string {
	whats := make([]string, 0, len(errs))
	for _, e := range errs {
		whats = append(whats, fmt.Sprintf("op %d: %s", e.OpIndex, e.What))
	}
	return strings.Join(whats, "; ")
}

// destroyUnusedLease destroys the lock session of a Register that failed. It
// runs on a fresh context, because the caller's may be what failed it, and a
// transaction whose reply was lost may have stored the entry under this lease.
// It can therefore outlive the caller's deadline.
func (c *consulSessionStore) destroyUnusedLease(lease string) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultConsulTimeout)
	defer cancel()
	if _, err := c.client.Session().Destroy(lease, (&api.WriteOptions{}).WithContext(ctx)); err != nil {
		c.logger.Warn("failed to destroy an unused consul lock session", "lease", lease, "error", err)
	}
}

// Release destroys reg's lock session. Consul deletes the entry with it only
// while that lock session still holds it, so a registration that was taken
// over leaves its successor's entry in place.
func (c *consulSessionStore) Release(ctx context.Context, reg *Registration) error {
	return c.release(ctx, reg.ID(), reg.lease)
}

func (c *consulSessionStore) release(ctx context.Context, sessionID, lease string) error {
	wo := (&api.WriteOptions{}).WithContext(ctx)
	err := retry.Do(
		func() error {
			if _, err := c.client.Session().Destroy(lease, wo); err != nil {
				return fmt.Errorf("failed to destroy consul lock session: %w", err)
			}
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.Debug("retrying consul release operation",
				"operation", "release",
				"attempt", n+1,
				"error", err,
			)
		}),
	)

	if err != nil {
		return err
	}

	c.forget(sessionID, lease)

	c.logger.Debug("released session lock in consul",
		"session", sessionID,
		"lease", lease,
	)

	return nil
}

// forget drops lease from this instance's record of sessionID, and the cache
// entry only if lease holds it. Any other lease it holds the ID under, such as
// a rebuild's, stays tracked, and the cache still describes the entry it
// holds; an entry another registration holds, such as another node's
// takeover, stays too: the release didn't touch it.
func (c *consulSessionStore) forget(sessionID, lease string) {
	c.heldMu.Lock()
	defer c.heldMu.Unlock()
	if leases, ok := c.held[sessionID]; ok {
		delete(leases, lease)
		if len(leases) == 0 {
			delete(c.held, sessionID)
		}
	}
	c.cache.Delete(sessionID, lease)
}

// Renew renews reg's lock session, and checks that it still holds reg's
// entry. Consul answers a lock session it no longer has with no entry and no
// error, which is a definite loss, unlike a failed renewal. A takeover from
// another node moves the entry to that node's lock session and leaves this
// one alive, so a renewal that succeeds says nothing about the entry: an
// entry that is gone, or held by another lock session, is a definite loss too.
// A transport error, renewing or reading, says nothing either way, and is
// returned as it came.
func (c *consulSessionStore) Renew(ctx context.Context, reg *Registration) error {
	entry, _, err := c.client.Session().Renew(reg.lease, (&api.WriteOptions{}).WithContext(ctx))
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("session %s: consul lock session %s: %w", reg.ID(), reg.lease, ErrLeaseLost)
	}
	pair, _, err := c.client.KV().Get(c.SessionKey(reg.ID()), (&api.QueryOptions{}).WithContext(ctx))
	if err != nil {
		return err
	}
	if pair == nil {
		return fmt.Errorf("session %s: the entry is gone: %w", reg.ID(), ErrLeaseLost)
	}
	if pair.Session != reg.lease {
		return fmt.Errorf("session %s: held by consul lock session %q, not %s: %w", reg.ID(), pair.Session, reg.lease, ErrLeaseLost)
	}
	return nil
}

func (c *consulSessionStore) LeaseTTL() time.Duration {
	return c.ttl
}

// Get session data with hybrid read-through cache
func (c *consulSessionStore) Get(sessionID string) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Try local cache first for instant lookup
	if session, exists := c.cache.Get(sessionID); exists {
		c.logger.Debug("retrieved session data from cache",
			"session", sessionID,
			"node", session.NodeAddr,
		)
		return session, nil
	}

	// Cache miss - fetch from Consul for strong consistency
	return c.getFromConsulAndCache(context.Background(), sessionID)
}

// GetFresh reads sessionID from Consul even when the cache has it, since the
// watch can trail a registration that has moved to another node.
func (c *consulSessionStore) GetFresh(ctx context.Context, sessionID string) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}
	return c.getFromConsulAndCache(ctx, sessionID)
}

// getFromConsulAndCache fetches session from Consul and updates local cache
func (c *consulSessionStore) getFromConsulAndCache(ctx context.Context, sessionID string) (*Session, error) {
	kvStoreKey := c.SessionKey(sessionID)
	qo := (&api.QueryOptions{}).WithContext(ctx)

	// Before the read, as for a registration's reply.
	epoch := c.cache.Epoch()

	var (
		session *Session
		index   uint64
		lease   string
		goneAt  uint64 // the index of a read that found no entry
	)
	err := retry.Do(
		func() error {
			kvPair, meta, err := c.client.KV().Get(kvStoreKey, qo)
			if err != nil {
				return fmt.Errorf("failed to get session data: %w", err)
			}
			if kvPair == nil {
				goneAt = meta.LastIndex
				return &ErrSessionNotFound{SessionID: sessionID}
			}

			var s Session
			if err := json.Unmarshal(kvPair.Value, &s); err != nil {
				return fmt.Errorf("failed to unmarshal session data: %w", err)
			}

			session, index, lease = &s, kvPair.ModifyIndex, kvPair.Session
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.RetryIf(func(err error) bool {
			// Don't retry if session is not found - it's a business logic error, not a network error
			var notFoundErr *ErrSessionNotFound
			return !errors.As(err, &notFoundErr)
		}),
		retry.OnRetry(func(n uint, err error) {
			c.logger.Debug("retrying consul get operation",
				"operation", "get_from_consul",
				"attempt", n+1,
				"error", err,
			)
		}),
	)

	if err != nil {
		// A cached entry the read found gone would otherwise go on routing
		// guests to a host that has left until the watch delivers the removal,
		// which on a quiet relay can be a long way off.
		var notFound *ErrSessionNotFound
		if errors.As(err, &notFound) {
			c.cache.Evict(sessionID, goneAt, epoch)
		}
		return nil, err
	}

	// Update local cache with fetched data
	c.cache.Set(sessionID, cachedSession{session: session, index: index, lease: lease}, epoch)

	c.logger.Debug("retrieved session data from consul and cached",
		"session", sessionID,
		"node", session.NodeAddr,
	)

	return session, nil
}

// Delete releases every lock session this instance registered sessionID under,
// if any; the one that holds the entry takes it with it. An entry it doesn't
// hold is another registration's, or no one's, and not this instance's to
// remove.
func (c *consulSessionStore) Delete(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	c.heldMu.Lock()
	leases := c.heldLeases(sessionID)
	c.heldMu.Unlock()
	if len(leases) == 0 {
		c.logger.Debug("not deleting a session this instance doesn't hold", "session", sessionID)
		return nil
	}

	var errs []error
	for _, lease := range leases {
		if err := c.release(context.Background(), sessionID, lease); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// heldEntry is a session ID and a lock session this instance holds it under.
type heldEntry struct {
	id, lease string
}

// BatchDelete deletes those of sessionIDs this instance holds, each only while
// its lock session still holds it. Shutdown cleanup deletes from a listing that
// can be stale by then, and an entry another node took over since must survive
// it. An ID held under several leases is tried under each: the one that holds
// the entry deletes it, and the others are lost holds.
//
// A transaction holds at most one entry per ID. Consul goes on through a
// transaction's operations after one fails, so a second pair for the same key
// would find it deleted by the first, and that failure would look like the
// lease losing its hold when it hadn't. Each ID's nth lease is therefore
// tried in the nth round.
func (c *consulSessionStore) BatchDelete(sessionIDs []string) error {
	c.heldMu.Lock()
	var rounds [][]heldEntry
	seen := make(map[string]bool, len(sessionIDs))
	for _, id := range sessionIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		for n, lease := range c.heldLeases(id) {
			if n == len(rounds) {
				rounds = append(rounds, nil)
			}
			rounds[n] = append(rounds[n], heldEntry{id: id, lease: lease})
		}
	}
	c.heldMu.Unlock()

	// Consul's official transaction limit is 64 operations, and each entry
	// takes two: the session check and the delete.
	// Reference: https://developer.hashicorp.com/consul/api-docs/txn
	const maxBatchSize = 32

	deleted := 0
	for _, entries := range rounds {
		for i := 0; i < len(entries); i += maxBatchSize {
			end := min(i+maxBatchSize, len(entries))

			done, err := c.deleteBatch(entries[i:end])
			for _, e := range done {
				c.forget(e.id, e.lease)
			}
			deleted += len(done)
			if err != nil {
				return err
			}
		}
	}

	c.logger.Debug("batch deleted sessions from consul and cache", "requested", len(sessionIDs), "deleted", deleted)
	return nil
}

// deleteBatch deletes each entry its lock session still holds, and returns the
// ones it deleted. A transaction that rolls back names the operations that
// failed. A failed session check whose entry is gone, or held by another lock
// session, is dropped and the rest are tried again. Any other failure, such as
// a permission denial, is returned, as is a rollback that names nothing that
// can be dropped: retrying it would loop.
func (c *consulSessionStore) deleteBatch(entries []heldEntry) ([]heldEntry, error) {
	for len(entries) > 0 {
		ops := make(api.KVTxnOps, 0, 2*len(entries))
		for _, e := range entries {
			kvStoreKey := c.SessionKey(e.id)
			ops = append(ops,
				&api.KVTxnOp{Verb: api.KVCheckSession, Key: kvStoreKey, Session: e.lease},
				&api.KVTxnOp{Verb: api.KVDelete, Key: kvStoreKey},
			)
		}

		var (
			ok   bool
			resp *api.KVTxnResponse
		)
		err := retry.Do(
			func() error {
				var err error
				ok, resp, _, err = c.client.KV().Txn(ops, nil)
				if err != nil {
					return fmt.Errorf("failed to execute batch delete transaction: %w", err)
				}
				return nil
			},
			retry.Attempts(DefaultMaxRetries),
			retry.Delay(DefaultRetryDelay),
			retry.OnRetry(func(n uint, err error) {
				c.logger.Debug("retrying consul batch delete operation",
					"operation", "batch_delete",
					"attempt", n+1,
					"count", len(entries),
					"error", err,
				)
			}),
		)
		if err != nil {
			return nil, err
		}
		if ok {
			return entries, nil
		}

		failed := make(map[int]bool, len(resp.Errors))
		for _, e := range resp.Errors {
			// Each entry is a session check followed by its delete.
			i := e.OpIndex / 2
			if e.OpIndex < 0 || e.OpIndex%2 != 0 || i >= len(entries) || !c.lostHold(entries[i]) {
				return nil, fmt.Errorf("batch delete transaction failed: %s", describeTxnErrors(resp.Errors))
			}
			failed[i] = true
		}
		if len(failed) == 0 {
			return nil, fmt.Errorf("batch delete transaction rolled back without naming an operation")
		}
		rest := make([]heldEntry, 0, len(entries)-len(failed))
		for i, e := range entries {
			if !failed[i] {
				rest = append(rest, e)
			}
		}
		c.logger.Debug("skipping sessions this instance no longer holds",
			"count", len(entries)-len(rest),
			"errors", describeTxnErrors(resp.Errors),
		)
		entries = rest
	}
	return nil, nil
}

// lostHold reports whether e's lock session no longer holds its entry: the
// entry is gone, or another lock session holds it. That is the one reason a
// session check fails that makes the entry not this instance's to delete. It
// reads Consul rather than the failure's text, and a read that fails reports
// false.
func (c *consulSessionStore) lostHold(e heldEntry) bool {
	pair, _, err := c.client.KV().Get(c.SessionKey(e.id), nil)
	return err == nil && (pair == nil || pair.Session != e.lease)
}

// List all sessions from Consul
func (c *consulSessionStore) List() ([]*Session, error) {
	var sessions []*Session

	err := retry.Do(
		func() error {
			pairs, _, err := c.client.KV().List(c.SessionsKey(), nil)
			if err != nil {
				return fmt.Errorf("failed to list sessions: %w", err)
			}

			sessions = make([]*Session, 0, len(pairs))
			for _, pair := range pairs {
				var session Session
				if err := json.Unmarshal(pair.Value, &session); err != nil {
					// Skip invalid sessions but continue processing
					c.logger.Warn("failed to unmarshal session, skipping", "error", err, "key", pair.Key)
					continue
				}
				sessions = append(sessions, &session)
			}
			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.Debug("retrying consul list operation",
				"operation", "list",
				"attempt", n+1,
				"error", err,
			)
		}),
	)

	if err != nil {
		return nil, err
	}

	c.logger.Debug("listed sessions from consul", "count", len(sessions))
	return sessions, nil
}

func (c *consulSessionStore) NodeName() string {
	return path.Join(c.keyPrefix, DefaultKeyPrefix)
}

// SessionKey generates the Consul KV store key for a session
func (c *consulSessionStore) SessionKey(sessionID string) string {
	return path.Join(c.keyPrefix, "sessions", sessionID)
}

func (c *consulSessionStore) SessionsKey() string {
	return path.Join(c.keyPrefix, "sessions")
}

// KeyPrefix returns the root key prefix used by this store (useful for cleanup in tests)
func (c *consulSessionStore) KeyPrefix() string {
	return c.keyPrefix + "/"
}

// registerNode registers this node with Consul
func (c *consulSessionStore) registerNode() error {
	_, err := c.client.Catalog().Register(&api.CatalogRegistration{
		Node:    c.NodeName(),
		Address: UnusedNodeAddress, // not used but required
	}, nil)
	if err != nil {
		return fmt.Errorf("register node %q: %w", c.NodeName(), err)
	}
	return nil
}

// createConsulLockSession creates a Consul session for distributed locking
func (c *consulSessionStore) createConsulLockSession(sessionID string) *api.SessionEntry {
	return &api.SessionEntry{
		Name:     sessionID,
		Node:     c.NodeName(),
		TTL:      c.ttl.String(),
		Behavior: api.SessionBehaviorDelete,
		// For the lock-delay after a lock session ends, Consul refuses to lock
		// the keys it held, which holds up registering its ID again after a
		// lost lease or a release. 1 ms is the smallest delay the Go API sends:
		// it drops a zero, and Consul then applies its default of 15 s.
		LockDelay: time.Millisecond,
	}
}

// startSessionWatch initializes the Consul watch to maintain full session replica
func (c *consulSessionStore) startSessionWatch(cfg *api.Config) error {
	// Create watch plan for all sessions
	params := map[string]interface{}{
		"type":   "keyprefix",
		"prefix": c.SessionsKey(),
		"token":  cfg.Token,
	}

	watchPlan, err := watch.Parse(params)
	if err != nil {
		return fmt.Errorf("failed to create watch plan: %w", err)
	}

	// Set up the handler to update local session replica
	watchPlan.Handler = func(idx uint64, data interface{}) {
		if kvPairs, ok := data.(api.KVPairs); ok {
			c.updateSessionReplica(idx, kvPairs)
		}
	}

	c.watchPlan = watchPlan

	// Create a separate config for watch operations with longer timeout
	// Consul watches use long-polling and need extended timeouts
	watchConfig := *cfg // Copy the config
	watchConfig.HttpClient = &http.Client{
		Timeout: DefaultWatchTimeout, // Allow long-polling for Consul watches
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		},
	}

	// Start watching in background
	go func() {
		c.logger.Info("starting session watch for full replication")
		if err := watchPlan.RunWithConfig(watchConfig.Address, &watchConfig); err != nil {
			c.logger.Error("session watch failed", "error", err)
		}
	}()

	return nil
}

// updateSessionReplica updates the local session replica based on Consul
// data: every session under the prefix as of index, which is no earlier than
// any write it includes. Then it hands the same view to the observers.
func (c *consulSessionStore) updateSessionReplica(index uint64, kvPairs api.KVPairs) {
	// Create new session map from Consul data
	newSessions := make(map[string]cachedSession)
	// The observers get a map of their own. The cache takes newSessions over,
	// and its writes go on changing it once ReplaceAll returns.
	entries := make(map[string]*Session, len(kvPairs))

	for _, kvPair := range kvPairs {
		var session Session
		if err := json.Unmarshal(kvPair.Value, &session); err != nil {
			c.logger.Warn("failed to unmarshal session data", "error", err, "key", kvPair.Key)
			continue
		}

		// Use session.ID from the unmarshaled value directly
		newSessions[session.ID] = cachedSession{session: &session, index: kvPair.ModifyIndex, lease: kvPair.Session}
		entries[session.ID] = &session
	}

	// Atomically replace cache contents. The cache takes the view before the
	// observers see it, so a read of the cache made after an observer has
	// acted on the view finds that view, or a later one.
	epoch := c.cache.ReplaceAll(index, newSessions)

	c.observersMu.Lock()
	observers := slices.Clone(c.observers)
	c.observersMu.Unlock()
	for _, fn := range observers {
		fn(epoch, index, entries)
	}
}

// Observe has fn called with every watch delivery, after the cache has taken
// it. See SessionManager.Observe.
func (c *consulSessionStore) Observe(fn func(epoch, index uint64, entries map[string]*Session)) {
	c.observersMu.Lock()
	defer c.observersMu.Unlock()
	c.observers = append(c.observers, fn)
}

// Close gracefully stops the session watch and cleans up resources
func (c *consulSessionStore) Close() error {
	if c.watchPlan != nil {
		c.watchPlan.Stop()
	}
	return nil
}

// HasInCache checks if a session exists in the local cache (useful for testing watch functionality)
func (c *consulSessionStore) HasInCache(sessionID string) bool {
	return c.cache.Has(sessionID)
}

// memorySessionStore is a simple in-memory implementation for testing/fallback
type memorySessionStore struct {
	sessions map[string]*Session
	logger   *slog.Logger
	mutex    sync.RWMutex
}

// newMemorySessionStore creates a new MemorySessionStore
func newMemorySessionStore(logger *slog.Logger) *memorySessionStore {
	return &memorySessionStore{
		sessions: make(map[string]*Session),
		logger:   logger,
	}
}

// Register stores session as a fresh registration.
func (m *memorySessionStore) Register(_ context.Context, session *Session) (*Registration, error) {
	return m.register(session, mayRegister)
}

// Reregister stores reg's session again, over its own entry too.
func (m *memorySessionStore) Reregister(_ context.Context, reg *Registration) (*Registration, error) {
	return m.register(reg.Session, mayRebuild)
}

// register stores session, replacing a stored entry only where may allows.
func (m *memorySessionStore) register(session *Session, may func(next, cur *Session) bool) (*Registration, error) {
	confirmed := time.Now()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if cur, ok := m.sessions[session.ID]; ok && !may(session, cur) {
		return nil, supersededError(session, cur)
	}
	m.sessions[session.ID] = session
	m.logger.Debug("stored session data in memory",
		"session", session.ID,
		"node", session.NodeAddr,
		"generation", session.Generation,
	)
	return &Registration{Session: session, ConfirmedAt: confirmed}, nil
}

// Release deletes reg's entry only while it is still reg's, so a superseded
// registration's cleanup leaves its successor in place.
func (m *memorySessionStore) Release(_ context.Context, reg *Registration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if cur, ok := m.sessions[reg.ID()]; ok && sameIdentity(cur, reg.Session) {
		delete(m.sessions, reg.ID())
		m.logger.Debug("released session data from memory",
			"session", reg.ID(),
			"generation", reg.Generation(),
		)
	}
	return nil
}

// Renew has no lease to extend in memory. It reports whether reg still holds
// its entry.
func (m *memorySessionStore) Renew(_ context.Context, reg *Registration) error {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if cur, ok := m.sessions[reg.ID()]; ok && sameIdentity(cur, reg.Session) {
		return nil
	}
	return fmt.Errorf("session %s: %w", reg.ID(), ErrLeaseLost)
}

// LeaseTTL is 0: an entry in memory lasts as long as the process.
func (m *memorySessionStore) LeaseTTL() time.Duration {
	return 0
}

func (m *memorySessionStore) Get(sessionID string) (*Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, &ErrSessionNotFound{SessionID: sessionID}
	}
	return session, nil
}

// GetFresh is Get: a memory store has no cache to skip.
func (m *memorySessionStore) GetFresh(_ context.Context, sessionID string) (*Session, error) {
	return m.Get(sessionID)
}

func (m *memorySessionStore) Delete(sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.sessions, sessionID)
	m.logger.Debug("deleted session data from memory",
		"session", sessionID,
	)
	return nil
}

// BatchDelete multiple sessions efficiently from memory
func (m *memorySessionStore) BatchDelete(sessionIDs []string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, sessionID := range sessionIDs {
		delete(m.sessions, sessionID)
	}

	m.logger.Debug("batch deleted sessions from memory", "count", len(sessionIDs))
	return nil
}

// List all sessions from memory
func (m *memorySessionStore) List() ([]*Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}

	m.logger.Debug("listed sessions from memory", "count", len(sessions))
	return sessions, nil
}

// Observe does nothing: every write to a memory store is this process's own.
func (m *memorySessionStore) Observe(func(epoch, index uint64, entries map[string]*Session)) {}

// Close cleans up memory store resources (no-op for memory store)
func (m *memorySessionStore) Close() error {
	return nil
}

// NewSession creates Session from session parameters
func NewSession(sessionID, nodeAddr, hostUser string, hostPublicKeys, clientAuthorizedKeys [][]byte) *Session {
	var hostKeys []ssh.PublicKey
	for _, keyBytes := range hostPublicKeys {
		if key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes); err == nil {
			hostKeys = append(hostKeys, key)
		}
	}

	var clientKeys []ssh.PublicKey
	for _, keyBytes := range clientAuthorizedKeys {
		if key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes); err == nil {
			clientKeys = append(clientKeys, key)
		}
	}

	return &Session{
		ID:                   sessionID,
		NodeAddr:             nodeAddr,
		HostUser:             hostUser,
		HostPublicKeys:       hostKeys,
		ClientAuthorizedKeys: clientKeys,
	}
}

// SessionManager provides a high-level interface for session management,
// combining session storage with connection ID encoding based on routing mode
type SessionManager struct {
	store         SessionStore
	encodeDecoder routing.EncodeDecoder
}

// SessionManagerConfig holds configuration for creating a SessionManager
type SessionManagerConfig struct {
	Mode      routing.Mode
	Logger    *slog.Logger
	ConsulURL *url.URL
	ConsulTTL time.Duration
}

// SessionManagerOption is a functional option for configuring SessionManager
type SessionManagerOption func(*SessionManagerConfig)

// WithSessionManagerLogger sets the logger for the session manager
func WithSessionManagerLogger(logger *slog.Logger) SessionManagerOption {
	return func(c *SessionManagerConfig) {
		c.Logger = logger
	}
}

// WithSessionManagerConsulURL sets the Consul URL for consul mode
func WithSessionManagerConsulURL(consulURL *url.URL) SessionManagerOption {
	return func(c *SessionManagerConfig) {
		c.ConsulURL = consulURL
	}
}

// WithSessionManagerConsulTTL sets the session TTL for consul mode
func WithSessionManagerConsulTTL(ttl time.Duration) SessionManagerOption {
	return func(c *SessionManagerConfig) {
		c.ConsulTTL = ttl
	}
}

// NewSessionManager creates a new SessionManager with the specified routing mode and options
//
// Examples:
//
//	// Embedded mode (simple, with default logger)
//	sm, err := NewSessionManager(routing.ModeEmbedded)
//
//	// Embedded mode with custom logger
//	sm, err := NewSessionManager(routing.ModeEmbedded, WithSessionManagerLogger(logger))
//
//	// Consul mode with minimal configuration
//	sm, err := NewSessionManager(routing.ModeConsul, WithSessionManagerConsulURL("http://localhost:8500"))
//
//	// Consul mode with full configuration
//	sm, err := NewSessionManager(routing.ModeConsul,
//	    WithSessionManagerLogger(logger),
//	    WithSessionManagerConsulURL("http://consul.example.com:8500"),
//	    WithSessionManagerConsulTTL(1*time.Hour))
func NewSessionManager(mode routing.Mode, opts ...SessionManagerOption) (*SessionManager, error) {
	config := &SessionManagerConfig{
		Mode:      mode,
		Logger:    slog.Default(),
		ConsulTTL: DefaultSessionTTL,
	}

	// Apply all options
	for _, opt := range opts {
		opt(config)
	}

	switch mode {
	case routing.ModeEmbedded:
		return newEmbeddedSessionManager(config.Logger), nil
	case routing.ModeConsul:
		return newConsulSessionManager(config.ConsulURL, config.ConsulTTL, config.Logger)
	default:
		return nil, fmt.Errorf("unsupported routing mode: %s", mode)
	}
}

// newSessionManagerWithStore creates a SessionManager with explicit store and encoder (for advanced testing)
func newSessionManagerWithStore(store SessionStore, encodeDecoder routing.EncodeDecoder) *SessionManager {
	return &SessionManager{
		store:         store,
		encodeDecoder: encodeDecoder,
	}
}

// newEmbeddedSessionManager creates a SessionManager for embedded mode with memory storage
func newEmbeddedSessionManager(logger *slog.Logger) *SessionManager {
	store := newMemorySessionStore(logger)
	encodeDecoder := routing.NewEncodeDecoder(routing.ModeEmbedded)
	return newSessionManagerWithStore(store, encodeDecoder)
}

// newConsulSessionManager creates a SessionManager for consul mode with Consul storage
func newConsulSessionManager(consulURL *url.URL, ttl time.Duration, logger *slog.Logger) (*SessionManager, error) {
	store, err := newConsulSessionStore(consulURL, ttl, logger)
	if err != nil {
		return nil, err
	}
	encodeDecoder := routing.NewEncodeDecoder(routing.ModeConsul)
	return newSessionManagerWithStore(store, encodeDecoder), nil
}

// CreateSession stores the session and returns the encoded SSH user identifier
func (sm *SessionManager) CreateSession(session *Session) (string, error) {
	_, sshUser, err := sm.Register(context.Background(), session)
	return sshUser, err
}

// Register stores s as a fresh registration, which needs its ID absent or a
// higher generation than the stored one, and returns its handle and the
// encoded SSH user identifier. A Register that fails may outlast ctx by up to
// DefaultConsulTimeout, while the store destroys a lease it created.
func (sm *SessionManager) Register(ctx context.Context, s *Session) (*Registration, string, error) {
	reg, err := sm.store.Register(ctx, s)
	if err != nil {
		return nil, "", err
	}

	// Encode the SSH user identifier using the encoder
	return reg, sm.encodeDecoder.Encode(s.ID, s.NodeAddr), nil
}

// Release removes reg's entry if reg still holds it.
func (sm *SessionManager) Release(ctx context.Context, reg *Registration) error {
	return sm.store.Release(ctx, reg)
}

// Renew keeps reg's entry alive; see SessionStore.Renew for its errors.
func (sm *SessionManager) Renew(ctx context.Context, reg *Registration) error {
	return sm.store.Renew(ctx, reg)
}

// Reregister rebuilds reg after a known loss: the same registration, stored
// again with a lease of its own. Unlike Register it may replace an entry of
// reg's own identity; only reg's lease keeper calls it. The handle it returns
// is Same as reg. Release reg afterwards only if its lease is non-empty and
// differs from the new handle's: a store without leases keeps one entry for
// both handles, and releasing reg there would delete the entry just rebuilt.
func (sm *SessionManager) Reregister(ctx context.Context, reg *Registration) (*Registration, error) {
	return sm.store.Reregister(ctx, reg)
}

// Observe has fn called with each view of every entry the store's watch
// delivers: entries maps each session ID to its stored session, as of index in
// epoch. Indexes order only within an epoch, which advances when the watch's
// index goes backwards; a Registration records both. fn runs on the watch's
// goroutine and holds up the next delivery, so it must not make store calls;
// entries is shared with the other observers, and is theirs only to read. A
// store no other writer shares never calls fn.
func (sm *SessionManager) Observe(fn func(epoch, index uint64, entries map[string]*Session)) {
	sm.store.Observe(fn)
}

// LeaseTTL is how long an unrenewed registration lasts; 0 if it doesn't expire.
func (sm *SessionManager) LeaseTTL() time.Duration {
	return sm.store.LeaseTTL()
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	return sm.store.Get(sessionID)
}

// DeleteSession removes a session by ID
func (sm *SessionManager) DeleteSession(sessionID string) error {
	return sm.store.Delete(sessionID)
}

// shouldValidateSessionExistence returns true if session existence should be validated
// based on the current routing mode and operational requirements.
//
// Both embedded and Consul modes are valid deployment options:
// - Embedded mode: For single-node or simple deployments without external dependencies
// - Consul mode: For multi-node deployments requiring shared session state
func (sm *SessionManager) shouldValidateSessionExistence() bool {
	// In Consul mode: validate existence (shared store accessible across all nodes)
	// In embedded mode: skip validation (session data is local to each node)
	return sm.encodeDecoder.Mode() == routing.ModeConsul
}

// ResolveSSHUser resolves an SSH username by decoding it and conditionally validating session existence
// In embedded mode: only decodes (session may be on another node)
// In consul mode: decodes and validates (shared store across all nodes)
func (sm *SessionManager) ResolveSSHUser(sshUser string) (sessionID, nodeAddr string, err error) {
	sessionID, nodeAddr, _, err = sm.lookupSSHUser(sshUser)
	return sessionID, nodeAddr, err
}

// lookupSSHUser is ResolveSSHUser, also returning the session it read, so a
// caller can take the node, the generation and the keys from that one read. It
// is nil in embedded mode, which reads nothing. Only a failed read is a
// lookupError: a user that doesn't decode is the guest's own mistake.
func (sm *SessionManager) lookupSSHUser(sshUser string) (sessionID, nodeAddr string, session *Session, err error) {
	// Decode the SSH user using our encoder
	sessionID, nodeAddr, err = sm.encodeDecoder.Decode(sshUser)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to decode SSH user: %w", err)
	}

	// Validate session existence based on routing mode strategy
	if sm.shouldValidateSessionExistence() {
		session, err = sm.store.Get(sessionID)
		if err != nil {
			return "", "", nil, &lookupError{fmt.Errorf("looking up session %s: %w", sessionID, err)}
		}

		return session.ID, session.NodeAddr, session, nil
	}

	return sessionID, nodeAddr, nil, nil
}

// Route is where a guest's upstream was sent: the node, and the registration
// that was current when it was resolved.
type Route struct {
	NodeAddr   string
	Generation uint64
}

// RefreshRoute reads sshUser's session from the store itself, skipping any
// cache, and reports whether it has moved from attempted to another node or
// another registration. It compares with the route an attempt was actually
// sent on, never with the cache: the watch may have updated that while the
// attempt was failing, and would then hide the move.
func (sm *SessionManager) RefreshRoute(ctx context.Context, sshUser string, attempted Route) (fresh *Session, moved bool, err error) {
	sessionID, _, err := sm.encodeDecoder.Decode(sshUser)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode SSH user: %w", err)
	}
	fresh, err = sm.store.GetFresh(ctx, sessionID)
	if err != nil {
		return nil, false, err
	}
	return fresh, fresh.NodeAddr != attempted.NodeAddr || fresh.Generation != attempted.Generation, nil
}

// GetEncodeDecoder returns the EncodeDecoder used by this session manager
func (sm *SessionManager) GetEncodeDecoder() routing.EncodeDecoder {
	return sm.encodeDecoder
}

// GetRoutingMode returns the routing mode of this session manager
func (sm *SessionManager) GetRoutingMode() routing.Mode {
	return sm.encodeDecoder.Mode()
}

// GetStore returns the underlying SessionStore for compatibility
func (sm *SessionManager) GetStore() SessionStore {
	return sm.store
}

// Shutdown cleans up sessions created by this node during server shutdown
// Shutdown deletes the sessions this node created and closes the store.
//
// ctx does not cancel the store calls -- List and BatchDelete take no context --
// but it does decide whether the deletes are still allowed to happen. A caller
// that has stopped waiting cancels it, and the listing this was about to delete
// from is then already stale: List reports whatever the store holds when it
// returns, and the node address it filters on identifies the node, not the
// process. Left unchecked, a cleanup abandoned by one server and unblocked
// after another had taken the same address would go on to delete the
// replacement's live sessions. Consul's BatchDelete deletes only entries this
// instance still holds, which spares them there; a store without that check
// would not.
func (sm *SessionManager) Shutdown(ctx context.Context, nodeAddr string) error {
	// Get all sessions
	sessions, err := sm.store.List()
	if err != nil {
		return fmt.Errorf("failed to list sessions for cleanup: %w", err)
	}

	if len(sessions) > 0 {
		// Collect session IDs for this node
		var sessionIDsToDelete []string
		for _, session := range sessions {
			if session.NodeAddr == nodeAddr {
				sessionIDsToDelete = append(sessionIDsToDelete, session.ID)
			}
		}

		// Batch delete sessions for this node
		if len(sessionIDsToDelete) > 0 {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("abandoned before deleting %d sessions: %w", len(sessionIDsToDelete), err)
			}
			if err := sm.store.BatchDelete(sessionIDsToDelete); err != nil {
				return fmt.Errorf("failed to batch delete sessions during shutdown: %w", err)
			}
		}
	}

	// Close the store to clean up resources (e.g., stop watch goroutines)
	if err := sm.store.Close(); err != nil {
		return fmt.Errorf("failed to close session store: %w", err)
	}

	return nil
}
