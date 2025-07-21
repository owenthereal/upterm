package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultSessionTTL    = 30 * time.Minute       // Default TTL for session data in Consul
	DefaultConsulPrefix  = "uptermd/sessions"     // Default prefix for Consul session keys
	DefaultConsulTimeout = 5 * time.Second        // Default timeout for Consul operations
	DefaultMaxRetries    = 3                      // Default number of retries for Consul operations
	DefaultRetryDelay    = 100 * time.Millisecond // Default delay between retries
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
}

// consulSessionStore implements SessionStore using Consul KV
type consulSessionStore struct {
	client *api.Client
	logger log.FieldLogger
	prefix string
	ttl    time.Duration
}

// newConsulSessionStore creates a new ConsulSessionStore
func newConsulSessionStore(consulAddr, prefix string, ttl time.Duration, logger log.FieldLogger) (*consulSessionStore, error) {
	config := api.DefaultConfig()
	if consulAddr != "" {
		config.Address = consulAddr
	}

	// Configure HTTP client with timeouts and connection pooling
	config.HttpClient = &http.Client{
		Timeout: DefaultConsulTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		},
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	if prefix == "" {
		prefix = DefaultConsulPrefix
	}

	if ttl == 0 {
		ttl = DefaultSessionTTL
	}

	return &consulSessionStore{
		client: client,
		logger: logger,
		prefix: prefix,
		ttl:    ttl,
	}, nil
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
	kvStoreKey := c.kvKey(session.ID)

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
			consulLockSessionID, _, err := c.client.Session().Create(consulLockSession, nil)
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

	// Log success only once, after all retries are done
	c.logger.WithFields(log.Fields{
		"session": session.ID,
		"node":    session.NodeAddr,
		"key":     kvStoreKey,
	}).Debug("stored session data in consul")

	return nil
}

// Get complete session data from Consul
func (c *consulSessionStore) Get(sessionID string) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID cannot be empty")
	}

	// Outside retry: deterministic operations
	kvStoreKey := c.kvKey(sessionID)
	var session *Session

	// Inside retry: only network operations
	err := retry.Do(
		func() error {
			kvPair, _, err := c.client.KV().Get(kvStoreKey, nil)
			if err != nil {
				return fmt.Errorf("failed to get session data: %w", err)
			}
			if kvPair == nil {
				return fmt.Errorf("session %s not found", sessionID)
			}

			session = &Session{}
			if err := json.Unmarshal(kvPair.Value, session); err != nil {
				return fmt.Errorf("failed to unmarshal session data: %w", err)
			}

			return nil
		},
		retry.Attempts(DefaultMaxRetries),
		retry.Delay(DefaultRetryDelay),
		retry.OnRetry(func(n uint, err error) {
			c.logger.WithFields(log.Fields{
				"operation": "get",
				"attempt":   n + 1,
				"error":     err,
			}).Debug("retrying consul get operation")
		}),
	)

	if err != nil {
		return nil, err
	}

	// Log success only once, after all retries are done
	c.logger.WithFields(log.Fields{
		"session": sessionID,
		"node":    session.NodeAddr,
	}).Debug("retrieved session data from consul")

	return session, nil
}

// Delete session data from Consul
func (c *consulSessionStore) Delete(sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	// Outside retry: deterministic operations
	kvStoreKey := c.kvKey(sessionID)

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

	// Log success only once, after all retries are done
	c.logger.WithFields(log.Fields{
		"session": sessionID,
		"key":     kvStoreKey,
	}).Debug("deleted session data from consul")

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

	c.logger.WithField("count", len(sessionIDs)).Debug("batch deleted sessions from consul")
	return nil
}

// deleteBatch deletes a batch of sessions using Consul transaction
func (c *consulSessionStore) deleteBatch(sessionIDs []string) error {
	ops := make([]*api.KVTxnOp, len(sessionIDs))
	for i, sessionID := range sessionIDs {
		kvStoreKey := c.kvKey(sessionID)
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
			pairs, _, err := c.client.KV().List(c.prefix, nil)
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

// kvKey generates the Consul KV store key for a session
func (c *consulSessionStore) kvKey(sessionID string) string {
	return fmt.Sprintf("%s/%s", c.prefix, sessionID)
}

// consulSessionName generates the Consul session name for locking
func (c *consulSessionStore) consulSessionName(sessionID string) string {
	return fmt.Sprintf("upterm-lock-%s", sessionID)
}

// createConsulLockSession creates a Consul session for distributed locking
func (c *consulSessionStore) createConsulLockSession(sessionID string) *api.SessionEntry {
	return &api.SessionEntry{
		Name:      c.consulSessionName(sessionID),
		TTL:       c.ttl.String(),
		Behavior:  api.SessionBehaviorDelete,
		LockDelay: time.Second,
	}
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
	Mode         routing.Mode
	Logger       log.FieldLogger
	ConsulAddr   string
	ConsulPrefix string
	ConsulTTL    time.Duration
}

// SessionManagerOption is a functional option for configuring SessionManager
type SessionManagerOption func(*SessionManagerConfig)

// WithSessionManagerLogger sets the logger for the session manager
func WithSessionManagerLogger(logger log.FieldLogger) SessionManagerOption {
	return func(c *SessionManagerConfig) {
		c.Logger = logger
	}
}

// WithSessionManagerConsulAddr sets the Consul address for consul mode
func WithSessionManagerConsulAddr(addr string) SessionManagerOption {
	return func(c *SessionManagerConfig) {
		c.ConsulAddr = addr
	}
}

// WithSessionManagerConsulPrefix sets the Consul key prefix for consul mode
func WithSessionManagerConsulPrefix(prefix string) SessionManagerOption {
	return func(c *SessionManagerConfig) {
		c.ConsulPrefix = prefix
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
//	sm, err := NewSessionManager(routing.ModeConsul, WithSessionManagerConsulAddr("localhost:8500"))
//
//	// Consul mode with full configuration
//	sm, err := NewSessionManager(routing.ModeConsul,
//	    WithSessionManagerLogger(logger),
//	    WithSessionManagerConsulAddr("consul.example.com:8500"),
//	    WithSessionManagerConsulPrefix("upterm/prod/sessions"),
//	    WithSessionManagerConsulTTL(1*time.Hour))
func NewSessionManager(mode routing.Mode, opts ...SessionManagerOption) (*SessionManager, error) {
	config := &SessionManagerConfig{
		Mode:         mode,
		Logger:       log.StandardLogger(), // Default logger
		ConsulTTL:    DefaultSessionTTL,
		ConsulPrefix: DefaultConsulPrefix,
	}

	// Apply all options
	for _, opt := range opts {
		opt(config)
	}

	switch mode {
	case routing.ModeEmbedded:
		return newEmbeddedSessionManager(config.Logger), nil
	case routing.ModeConsul:
		return newConsulSessionManager(config.ConsulAddr, config.ConsulPrefix, config.ConsulTTL, config.Logger)
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
func newConsulSessionManager(consulAddr, prefix string, ttl time.Duration, logger log.FieldLogger) (*SessionManager, error) {
	store, err := newConsulSessionStore(consulAddr, prefix, ttl, logger)
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

// ResolveSSHUser resolves an SSH username by decoding it and conditionally validating session existence
// In embedded mode: only decodes (session may be on another node)
// In consul mode: decodes and validates (shared store across all nodes)
func (sm *SessionManager) ResolveSSHUser(sshUser string) (sessionID, nodeAddr string, err error) {
	// Decode the SSH user using our encoder
	sessionID, nodeAddr, err = sm.encodeDecoder.Decode(sshUser)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode SSH user: %w", err)
	}

	// Only validate session existence in Consul mode
	// In embedded mode, the session might exist on another node
	if sm.encodeDecoder.Mode() == routing.ModeConsul {
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

	if len(sessions) == 0 {
		return nil
	}

	// Collect session IDs for this node
	var sessionIDsToDelete []string
	for _, session := range sessions {
		if session.NodeAddr == nodeAddr {
			sessionIDsToDelete = append(sessionIDsToDelete, session.ID)
		}
	}

	if len(sessionIDsToDelete) == 0 {
		return nil
	}

	// Batch delete sessions
	if err := sm.store.BatchDelete(sessionIDsToDelete); err != nil {
		return fmt.Errorf("failed to batch delete sessions during shutdown: %w", err)
	}

	return nil
}
