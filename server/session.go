package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	reflect "reflect"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/consul/api/watch"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// SessionNotFoundError represents a non-retryable session not found error
type SessionNotFoundError struct {
	SessionID string
}

func (e *SessionNotFoundError) Error() string {
	return fmt.Sprintf("session %s not found", e.SessionID)
}

const (
	DefaultSessionTTL      = 30 * time.Minute       // Default TTL for session data in Consul
	DefaultConsulTimeout   = 5 * time.Second        // Default timeout for Consul operations
	DefaultWatchTimeout    = 10 * time.Minute       // Default timeout for Consul watch operations (long-polling)
	DefaultMaxRetries      = 3                      // Default number of retries for Consul operations
	DefaultRetryDelay      = 100 * time.Millisecond // Default delay between retries
)

// Session represents the complete session information
type Session struct {
	ID                   string
	NodeAddr             string
	HostUser             string
	HostPublicKeys       []ssh.PublicKey
	ClientAuthorizedKeys []ssh.PublicKey
}

// MarshalJSON implements custom JSON marshaling for Session
func (s *Session) MarshalJSON() ([]byte, error) {
	type sessionJSON struct {
		ID                   string
		NodeAddr             string
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

// SessionStore defines the interface for session storage
type SessionStore interface {
	// Store complete session data
	Store(session *Session) error
	// Get complete session data
	Get(sessionID string) (*Session, error)
	// Delete session data
	Delete(sessionID string) error
	// BatchDelete multiple sessions efficiently
	BatchDelete(sessionIDs []string) error
	// List all sessions (for cleanup and management)
	List() ([]*Session, error)
	// Close cleans up resources and stops background processes
	Close() error
}

// sessionCache provides thread-safe in-memory caching for sessions
type sessionCache struct {
	sessions map[string]*Session
	mutex    sync.RWMutex
	logger   log.FieldLogger
}

// newSessionCache creates a new session cache
func newSessionCache(logger log.FieldLogger) *sessionCache {
	return &sessionCache{
		sessions: make(map[string]*Session),
		logger:   logger,
	}
}

// Get retrieves a session from cache
func (c *sessionCache) Get(sessionID string) (*Session, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	session, exists := c.sessions[sessionID]
	return session, exists
}

// Has checks if a session exists in cache without retrieving it (useful for testing)
func (c *sessionCache) Has(sessionID string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	_, exists := c.sessions[sessionID]
	return exists
}

// Set stores a session in cache
func (c *sessionCache) Set(sessionID string, session *Session) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.sessions[sessionID] = session
	c.logger.WithField("session", sessionID).Debug("cached session")
}

// Delete removes a session from cache
func (c *sessionCache) Delete(sessionID string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.sessions, sessionID)
	c.logger.WithField("session", sessionID).Debug("removed session from cache")
}

// BatchDelete removes multiple sessions from cache
func (c *sessionCache) BatchDelete(sessionIDs []string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, sessionID := range sessionIDs {
		delete(c.sessions, sessionID)
	}
	c.logger.WithField("count", len(sessionIDs)).Debug("batch removed sessions from cache")
}

// ReplaceAll atomically replaces all sessions in cache
func (c *sessionCache) ReplaceAll(newSessions map[string]*Session) (added, updated, deleted int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Calculate changes for logging
	for sessionID, newSession := range newSessions {
		if oldSession, exists := c.sessions[sessionID]; exists {
			if !reflect.DeepEqual(oldSession, newSession) {
				updated++
			}
		} else {
			added++
		}
	}

	// Count deleted sessions
	for sessionID := range c.sessions {
		if _, exists := newSessions[sessionID]; !exists {
			deleted++
		}
	}

	// Replace the entire session map atomically
	c.sessions = newSessions

	if added > 0 || updated > 0 || deleted > 0 {
		c.logger.WithFields(log.Fields{
			"total":   len(newSessions),
			"added":   added,
			"updated": updated,
			"deleted": deleted,
		}).Info("updated session cache")
	}

	return added, updated, deleted
}

// consulSessionStore implements SessionStore using Consul KV with hybrid read-through cache
type consulSessionStore struct {
	client    *api.Client
	logger    log.FieldLogger
	ttl       time.Duration
	keyPrefix string
	// Hybrid cache for instant lookups with fallback to Consul
	cache *sessionCache
	// Watch management
	watchPlan *watch.Plan
}

// newConsulSessionStore creates a new ConsulSessionStore
func newConsulSessionStore(consulURL *url.URL, ttl time.Duration, logger log.FieldLogger) (*consulSessionStore, error) {
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
		keyPrefix = "uptermd"
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

// Store complete session data in Consul
func (c *consulSessionStore) Store(session *Session) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	if session.ID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	// Outside retry: deterministic operations
	kvStoreKey := c.SessionKey(session.ID)

	// Serialize session data as JSON first to fail fast on marshaling errors
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Create a Consul session for distributed locking and TTL management
	consulLockSession := c.createConsulLockSession(session.ID)

	// Inside retry: only network operations
	err = retry.Do(
		func() error {
			consulLockSessionID, _, err := c.client.Session().CreateNoChecks(consulLockSession, nil)
			if err != nil {
				return fmt.Errorf("failed to create consul lock session: %w", err)
			}

			// Store the complete session data with distributed lock and TTL
			kvPair := &api.KVPair{
				Key:     kvStoreKey,
				Value:   sessionData,
				Session: consulLockSessionID,
			}

			lockAcquired, _, err := c.client.KV().Acquire(kvPair, nil)
			if err != nil {
				return fmt.Errorf("failed to store session data: %w", err)
			}
			if !lockAcquired {
				return fmt.Errorf("failed to acquire distributed lock for session %s", session.ID)
			}

			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.WithFields(log.Fields{
				"operation": "store",
				"attempt":   n + 1,
				"error":     err,
			}).Debug("retrying consul store operation")
		}),
	)

	if err != nil {
		return err
	}

	// Immediately update local cache for strong consistency
	c.cache.Set(session.ID, session)

	c.logger.WithFields(log.Fields{
		"session": session.ID,
		"node":    session.NodeAddr,
		"key":     kvStoreKey,
	}).Debug("stored session data in consul and cache")

	return nil
}

// Get session data with hybrid read-through cache
func (c *consulSessionStore) Get(sessionID string) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Try local cache first for instant lookup
	if session, exists := c.cache.Get(sessionID); exists {
		c.logger.WithFields(log.Fields{
			"session": sessionID,
			"node":    session.NodeAddr,
		}).Debug("retrieved session data from cache")
		return session, nil
	}

	// Cache miss - fetch from Consul for strong consistency
	return c.getFromConsulAndCache(sessionID)
}

// getFromConsulAndCache fetches session from Consul and updates local cache
func (c *consulSessionStore) getFromConsulAndCache(sessionID string) (*Session, error) {
	kvStoreKey := c.SessionKey(sessionID)

	var session *Session
	err := retry.Do(
		func() error {
			kvPair, _, err := c.client.KV().Get(kvStoreKey, nil)
			if err != nil {
				return fmt.Errorf("failed to get session data: %w", err)
			}
			if kvPair == nil {
				return &SessionNotFoundError{SessionID: sessionID}
			}

			var s Session
			if err := json.Unmarshal(kvPair.Value, &s); err != nil {
				return fmt.Errorf("failed to unmarshal session data: %w", err)
			}

			session = &s
			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.RetryIf(func(err error) bool {
			// Don't retry if session is not found - it's a business logic error, not a network error
			var notFoundErr *SessionNotFoundError
			return !errors.As(err, &notFoundErr)
		}),
		retry.OnRetry(func(n uint, err error) {
			c.logger.WithFields(log.Fields{
				"operation": "get_from_consul",
				"attempt":   n + 1,
				"error":     err,
			}).Debug("retrying consul get operation")
		}),
	)

	if err != nil {
		return nil, err
	}

	// Update local cache with fetched data
	c.cache.Set(sessionID, session)

	c.logger.WithFields(log.Fields{
		"session": sessionID,
		"node":    session.NodeAddr,
	}).Debug("retrieved session data from consul and cached")

	return session, nil
}

// Delete session data from Consul
func (c *consulSessionStore) Delete(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	// Outside retry: deterministic operations
	kvStoreKey := c.SessionKey(sessionID)

	// Inside retry: only network operations
	err := retry.Do(
		func() error {
			_, err := c.client.KV().Delete(kvStoreKey, nil)
			if err != nil {
				return fmt.Errorf("failed to delete session data: %w", err)
			}
			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.WithFields(log.Fields{
				"operation": "delete",
				"attempt":   n + 1,
				"error":     err,
			}).Debug("retrying consul delete operation")
		}),
	)

	if err != nil {
		return err
	}

	// Immediately remove from local cache for strong consistency
	c.cache.Delete(sessionID)

	c.logger.WithFields(log.Fields{
		"session": sessionID,
		"key":     kvStoreKey,
	}).Debug("deleted session data from consul and cache")

	return nil
}

// BatchDelete multiple sessions efficiently using Consul transactions
func (c *consulSessionStore) BatchDelete(sessionIDs []string) error {
	if len(sessionIDs) == 0 {
		return nil
	}

	// Consul's official transaction limit is 64 operations
	// Reference: https://developer.hashicorp.com/consul/api-docs/txn
	const maxBatchSize = 64

	for i := 0; i < len(sessionIDs); i += maxBatchSize {
		end := min(i+maxBatchSize, len(sessionIDs))

		if err := c.deleteBatch(sessionIDs[i:end]); err != nil {
			return err
		}
	}

	// Immediately remove from local cache for strong consistency
	c.cache.BatchDelete(sessionIDs)

	c.logger.WithField("count", len(sessionIDs)).Debug("batch deleted sessions from consul and cache")
	return nil
}

// deleteBatch deletes a batch of sessions using Consul transaction
func (c *consulSessionStore) deleteBatch(sessionIDs []string) error {
	ops := make([]*api.KVTxnOp, len(sessionIDs))
	for i, sessionID := range sessionIDs {
		kvStoreKey := c.SessionKey(sessionID)
		ops[i] = &api.KVTxnOp{
			Verb: api.KVDelete,
			Key:  kvStoreKey,
		}
	}

	return retry.Do(
		func() error {
			ok, response, _, err := c.client.KV().Txn(ops, nil)
			if err != nil {
				return fmt.Errorf("failed to execute batch delete transaction: %w", err)
			}
			if !ok {
				return fmt.Errorf("batch delete transaction failed: %v", response.Errors)
			}
			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.WithFields(log.Fields{
				"operation": "batch_delete",
				"attempt":   n + 1,
				"count":     len(sessionIDs),
				"error":     err,
			}).Debug("retrying consul batch delete operation")
		}),
	)
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
					c.logger.WithError(err).WithField("key", pair.Key).Warn("failed to unmarshal session, skipping")
					continue
				}
				sessions = append(sessions, &session)
			}
			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.WithFields(log.Fields{
				"operation": "list",
				"attempt":   n + 1,
				"error":     err,
			}).Debug("retrying consul list operation")
		}),
	)

	if err != nil {
		return nil, err
	}

	c.logger.WithField("count", len(sessions)).Debug("listed sessions from consul")
	return sessions, nil
}

func (c *consulSessionStore) NodeName() string {
	return path.Join(c.keyPrefix, "uptermd")
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
		Address: "localhost", // not used but required
	}, nil)
	if err != nil {
		return fmt.Errorf("register node %q: %w", c.NodeName(), err)
	}
	return nil
}

// createConsulLockSession creates a Consul session for distributed locking
func (c *consulSessionStore) createConsulLockSession(sessionID string) *api.SessionEntry {
	return &api.SessionEntry{
		Name:      sessionID,
		Node:      c.NodeName(),
		TTL:       c.ttl.String(),
		Behavior:  api.SessionBehaviorDelete,
		LockDelay: time.Second,
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
			c.updateSessionReplica(kvPairs)
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
			c.logger.WithError(err).Error("session watch failed")
		}
	}()

	return nil
}

// updateSessionReplica updates the local session replica based on Consul data
func (c *consulSessionStore) updateSessionReplica(kvPairs api.KVPairs) {
	// Create new session map from Consul data
	newSessions := make(map[string]*Session)

	for _, kvPair := range kvPairs {
		var session Session
		if err := json.Unmarshal(kvPair.Value, &session); err != nil {
			c.logger.WithError(err).WithField("key", kvPair.Key).Warn("failed to unmarshal session data")
			continue
		}

		// Use session.ID from the unmarshaled value directly
		newSessions[session.ID] = &session
	}

	// Atomically replace cache contents and get change statistics
	c.cache.ReplaceAll(newSessions)
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
	logger   log.FieldLogger
	mutex    sync.RWMutex
}

// newMemorySessionStore creates a new MemorySessionStore
func newMemorySessionStore(logger log.FieldLogger) *memorySessionStore {
	return &memorySessionStore{
		sessions: make(map[string]*Session),
		logger:   logger,
	}
}

func (m *memorySessionStore) Store(session *Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.sessions[session.ID] = session
	m.logger.WithFields(log.Fields{
		"session": session.ID,
		"node":    session.NodeAddr,
	}).Debug("stored session data in memory")
	return nil
}

func (m *memorySessionStore) Get(sessionID string) (*Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	return session, nil
}

func (m *memorySessionStore) Delete(sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.sessions, sessionID)
	m.logger.WithFields(log.Fields{
		"session": sessionID,
	}).Debug("deleted session data from memory")
	return nil
}

// BatchDelete multiple sessions efficiently from memory
func (m *memorySessionStore) BatchDelete(sessionIDs []string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, sessionID := range sessionIDs {
		delete(m.sessions, sessionID)
	}

	m.logger.WithField("count", len(sessionIDs)).Debug("batch deleted sessions from memory")
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

	m.logger.WithField("count", len(sessions)).Debug("listed sessions from memory")
	return sessions, nil
}

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
	Logger    log.FieldLogger
	ConsulURL *url.URL
	ConsulTTL time.Duration
}

// SessionManagerOption is a functional option for configuring SessionManager
type SessionManagerOption func(*SessionManagerConfig)

// WithSessionManagerLogger sets the logger for the session manager
func WithSessionManagerLogger(logger log.FieldLogger) SessionManagerOption {
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
		Logger:    log.StandardLogger(), // Default logger
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
func newEmbeddedSessionManager(logger log.FieldLogger) *SessionManager {
	store := newMemorySessionStore(logger)
	encodeDecoder := routing.NewEncodeDecoder(routing.ModeEmbedded)
	return newSessionManagerWithStore(store, encodeDecoder)
}

// newConsulSessionManager creates a SessionManager for consul mode with Consul storage
func newConsulSessionManager(consulURL *url.URL, ttl time.Duration, logger log.FieldLogger) (*SessionManager, error) {
	store, err := newConsulSessionStore(consulURL, ttl, logger)
	if err != nil {
		return nil, err
	}
	encodeDecoder := routing.NewEncodeDecoder(routing.ModeConsul)
	return newSessionManagerWithStore(store, encodeDecoder), nil
}

// CreateSession stores the session and returns the encoded SSH user identifier
func (sm *SessionManager) CreateSession(session *Session) (string, error) {
	if err := sm.store.Store(session); err != nil {
		return "", err
	}

	// Encode the SSH user identifier using the encoder
	return sm.encodeDecoder.Encode(session.ID, session.NodeAddr), nil
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
	// Decode the SSH user using our encoder
	sessionID, nodeAddr, err = sm.encodeDecoder.Decode(sshUser)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode SSH user: %w", err)
	}

	// Validate session existence based on routing mode strategy
	if sm.shouldValidateSessionExistence() {
		session, err := sm.store.Get(sessionID)
		if err != nil {
			return "", "", fmt.Errorf("session %s not found: %w", sessionID, err)
		}

		return session.ID, session.NodeAddr, nil
	}

	return sessionID, nodeAddr, nil
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
func (sm *SessionManager) Shutdown(nodeAddr string) error {
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
