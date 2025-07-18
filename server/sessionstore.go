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

// ConsulSessionStore implements SessionStore using Consul KV
type ConsulSessionStore struct {
	client *api.Client
	logger log.FieldLogger
	prefix string
	ttl    time.Duration
}

// NewConsulSessionStore creates a new ConsulSessionStore
func NewConsulSessionStore(consulAddr, prefix string, ttl time.Duration, logger log.FieldLogger) (*ConsulSessionStore, error) {
	config := api.DefaultConfig()
	if consulAddr != "" {
		config.Address = consulAddr
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	if prefix == "" {
		prefix = "upterm/sessions"
	}

	if ttl == 0 {
		ttl = 30 * time.Minute // Default TTL
	}

	return &ConsulSessionStore{
		client: client,
		logger: logger,
		prefix: prefix,
		ttl:    ttl,
	}, nil
}

// Store complete session data in Consul
func (c *ConsulSessionStore) Store(session *Session) error {
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
func (c *ConsulSessionStore) Get(sessionID string) (*Session, error) {
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
func (c *ConsulSessionStore) Delete(sessionID string) error {
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

// MemorySessionStore is a simple in-memory implementation for testing/fallback
type MemorySessionStore struct {
	sessions map[string]*Session
	logger   log.FieldLogger
	mutex    sync.RWMutex
}

// NewMemorySessionStore creates a new MemorySessionStore
func NewMemorySessionStore(logger log.FieldLogger) *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]*Session),
		logger:   logger,
	}
}

func (m *MemorySessionStore) Store(session *Session) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.sessions[session.ID] = session
	m.logger.WithFields(log.Fields{
		"session": session.ID,
		"node":    session.NodeAddr,
	}).Debug("stored session data in memory")
	return nil
}

func (m *MemorySessionStore) Get(sessionID string) (*Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	return session, nil
}

func (m *MemorySessionStore) Delete(sessionID string) error {
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
	store   SessionStore
	encoder routing.EncodeDecoder
}

// NewSessionManager creates a new SessionManager
func NewSessionManager(store SessionStore, routingMode routing.Mode) *SessionManager {
	return &SessionManager{
		store:   store,
		encoder: routing.NewEncodeDecoder(routingMode),
	}
}

// CreateSession stores the session and returns the encoded SSH user identifier
func (sm *SessionManager) CreateSession(session *Session) (string, error) {
	if err := sm.store.Store(session); err != nil {
		return "", err
	}

	// Encode the SSH user identifier using the encoder
	return sm.encoder.Encode(session.ID, session.NodeAddr), nil
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
	sessionID, nodeAddr, err = sm.encoder.Decode(sshUser)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode SSH user: %w", err)
	}

	// Only validate session existence in Consul mode
	// In embedded mode, the session might exist on another node
	if sm.encoder.Mode() == routing.ModeConsul {
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
	return sm.encoder
}

// GetRoutingMode returns the routing mode of this session manager
func (sm *SessionManager) GetRoutingMode() routing.Mode {
	return sm.encoder.Mode()
}

// GetStore returns the underlying SessionStore for compatibility
func (sm *SessionManager) GetStore() SessionStore {
	return sm.store
}
