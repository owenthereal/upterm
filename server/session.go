package server

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/owenthereal/upterm/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultSessionTTL   = 30 * time.Minute   // Default TTL for session data in Consul
	DefaultConsulPrefix = "uptermd/sessions" // Default prefix for Consul session keys
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
	key := fmt.Sprintf("%s/%s", c.prefix, session.ID)

	// Create a session for TTL support
	sessionID_consul := &api.SessionEntry{
		Name:      fmt.Sprintf("upterm-session-%s", session.ID),
		TTL:       c.ttl.String(),
		Behavior:  api.SessionBehaviorDelete,
		LockDelay: time.Second,
	}

	sessionResp, _, err := c.client.Session().Create(sessionID_consul, nil)
	if err != nil {
		return fmt.Errorf("failed to create consul session: %w", err)
	}

	// Serialize session data as JSON
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store the complete session data with session-based TTL
	pair := &api.KVPair{
		Key:     key,
		Value:   sessionBytes,
		Session: sessionResp,
	}

	success, _, err := c.client.KV().Acquire(pair, nil)
	if err != nil {
		return fmt.Errorf("failed to store session data: %w", err)
	}
	if !success {
		return fmt.Errorf("failed to acquire lock for session %s", session.ID)
	}

	c.logger.WithFields(log.Fields{
		"session": session.ID,
		"node":    session.NodeAddr,
		"key":     key,
	}).Debug("stored session data in consul")

	return nil
}

// Get complete session data from Consul
func (c *consulSessionStore) Get(sessionID string) (*Session, error) {
	key := fmt.Sprintf("%s/%s", c.prefix, sessionID)

	pair, _, err := c.client.KV().Get(key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}
	if pair == nil {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	var session Session
	if err := json.Unmarshal(pair.Value, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	c.logger.WithFields(log.Fields{
		"session": sessionID,
		"node":    session.NodeAddr,
	}).Debug("retrieved session data from consul")

	return &session, nil
}

// Delete session data from Consul
func (c *consulSessionStore) Delete(sessionID string) error {
	key := fmt.Sprintf("%s/%s", c.prefix, sessionID)

	_, err := c.client.KV().Delete(key, nil)
	if err != nil {
		return fmt.Errorf("failed to delete session data: %w", err)
	}

	c.logger.WithFields(log.Fields{
		"session": sessionID,
		"key":     key,
	}).Debug("deleted session data from consul")

	return nil
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
