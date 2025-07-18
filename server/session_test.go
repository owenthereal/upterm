package server

import (
	"os"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/routing"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

// This file contains comprehensive tests for the session management system.
// Tests are organized using testify suites for better structure and reusability:
// - EmbeddedModeTestSuite: Tests memory storage with embedded mode SessionManager
// - ConsulModeTestSuite: Tests Consul storage with consul mode SessionManager
// Consul tests automatically skip when Consul is not available.

// EmbeddedModeTestSuite tests the MemorySessionStore and embedded mode SessionManager
type EmbeddedModeTestSuite struct {
	suite.Suite

	sm     *SessionManager
	logger logrus.FieldLogger
}

func (suite *EmbeddedModeTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.sm = newEmbeddedSessionManager(suite.logger)
}

func (suite *EmbeddedModeTestSuite) TestStoreOperations() {
	store := suite.sm.GetStore()

	sessionID := "test-session"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
	}

	// Test Store
	err := store.Store(session)
	suite.NoError(err)

	// Test Store duplicate (should succeed - overwrites)
	err = store.Store(session)
	suite.NoError(err)

	// Test Get
	retrievedSession, err := store.Get(sessionID)
	suite.NoError(err)
	suite.Equal(session.ID, retrievedSession.ID)
	suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)

	// Test Update (Store is used for both create and update)
	session.NodeAddr = "192.168.1.100:2222"
	err = store.Store(session)
	suite.NoError(err)

	retrievedSession, err = store.Get(sessionID)
	suite.NoError(err)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)

	// Test Delete
	err = store.Delete(sessionID)
	suite.NoError(err)

	// Verify deletion
	_, err = store.Get(sessionID)
	suite.Error(err)

	// Test Delete non-existent (should succeed - idempotent)
	err = store.Delete("nonexistent")
	suite.NoError(err)
}

func (suite *EmbeddedModeTestSuite) TestSessionOperations() {
	// Test SessionManager behavior with embedded mode
	sessionID := "test-session-456"
	nodeAddr := "127.0.0.1:2222"
	session := &Session{
		ID:       sessionID,
		NodeAddr: nodeAddr,
	}

	// Test basic operations
	sshUser, err := suite.sm.CreateSession(session)
	suite.NoError(err)
	suite.Contains(sshUser, sessionID)

	// Test GetSession
	retrievedSession, err := suite.sm.GetSession(sessionID)
	suite.NoError(err)
	suite.Equal(sessionID, retrievedSession.ID)
	suite.Equal(nodeAddr, retrievedSession.NodeAddr)

	// Test DeleteSession
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)

	// Verify session was deleted
	_, err = suite.sm.GetSession(sessionID)
	suite.Error(err)
}

func (suite *EmbeddedModeTestSuite) TestResolveSSHUserHappyPath() {
	sessionID := "test-session-123"
	nodeAddr := "127.0.0.1:2222"
	session := &Session{
		ID:       sessionID,
		NodeAddr: nodeAddr,
	}

	// Test CreateSession
	sshUser, err := suite.sm.CreateSession(session)
	suite.NoError(err)
	suite.Contains(sshUser, sessionID)
	suite.Contains(sshUser, ":")

	// Verify it's using embedded mode
	suite.Equal(routing.ModeEmbedded, suite.sm.GetRoutingMode())

	// Test ResolveSSHUser with embedded encoding
	resolvedSessionID, resolvedNodeAddr, err := suite.sm.ResolveSSHUser(sshUser)
	suite.NoError(err)
	suite.Equal(sessionID, resolvedSessionID)
	suite.Equal(nodeAddr, resolvedNodeAddr)
}

func (suite *EmbeddedModeTestSuite) TestResolveSSHUserError() {
	testCases := []struct {
		input       string
		description string
	}{
		{"no-colon-here", "no colon separator"},
		{"", "empty string"},
		{"session:invalid-base64===!@#$", "invalid base64 characters"},
	}

	for _, tc := range testCases {
		suite.Run(tc.description, func() {
			_, _, err := suite.sm.ResolveSSHUser(tc.input)
			suite.Error(err)
		})
	}
}

func (suite *EmbeddedModeTestSuite) TestResolveSSHUserNoValidation() {
	// Embedded mode should not validate session existence (distributed scenario)
	sessionID := "nonexistent-session"
	nodeAddr := "127.0.0.1:2222"

	// Create SSH user for non-existent session using embedded encoding
	encodeDecoder := suite.sm.GetEncodeDecoder()
	sshUser := encodeDecoder.Encode(sessionID, nodeAddr)

	// Should return session info even if it doesn't exist in store
	resolvedSessionID, resolvedNodeAddr, err := suite.sm.ResolveSSHUser(sshUser)
	suite.NoError(err)
	suite.Equal(sessionID, resolvedSessionID)
	suite.Equal(nodeAddr, resolvedNodeAddr)
}

// ConsulModeTestSuite tests the ConsulSessionStore and consul mode SessionManager
type ConsulModeTestSuite struct {
	suite.Suite

	sm     *SessionManager
	client *api.Client
}

func (suite *ConsulModeTestSuite) SetupSuite() {
	// Skip if Consul is not available
	if !suite.isConsulAvailable() {
		suite.T().Skip("Consul not available - set CONSUL_ADDR or ensure Consul is running on localhost:8500")
	}

	sm, err := newConsulSessionManager(suite.consulAddr(), "uptermd-test/sessions", 5*time.Minute, logrus.New())
	suite.Require().NoError(err)
	suite.sm = sm

	// Setup client for cleanup
	client, err := suite.consulClient()
	suite.Require().NoError(err)
	suite.client = client
}

func (suite *ConsulModeTestSuite) TearDownSuite() {
	if suite.client != nil {
		// Clean up test data
		_, err := suite.client.KV().DeleteTree("uptermd-test/", nil)
		suite.NoError(err)
	}
}

func (suite *ConsulModeTestSuite) TestStoreOperations() {
	store := suite.sm.GetStore()

	sessionID := "test-consul-session"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
		HostUser: "testuser",
	}

	// Test Store
	err := store.Store(session)
	suite.NoError(err)

	// Test Get
	retrievedSession, err := store.Get(sessionID)
	suite.NoError(err)
	suite.Equal(session.ID, retrievedSession.ID)
	suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)
	suite.Equal(session.HostUser, retrievedSession.HostUser)

	// Test Update (requires delete first due to Consul session locking mechanism)
	// The ConsulSessionStore uses Acquire() which is designed for distributed locking,
	// so we need to delete the existing session before storing an updated version.
	err = store.Delete(sessionID)
	suite.NoError(err)

	session.NodeAddr = "192.168.1.100:2222"
	err = store.Store(session)
	suite.NoError(err)

	retrievedSession, err = store.Get(sessionID)
	suite.NoError(err)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)

	// Test Delete
	err = store.Delete(sessionID)
	suite.NoError(err)

	// Verify deletion
	_, err = store.Get(sessionID)
	suite.Error(err)
}

func (suite *ConsulModeTestSuite) TestSessionOperations() {
	sessionID := "test-factory-session"
	nodeAddr := "192.168.1.100:2222"
	session := &Session{
		ID:       sessionID,
		NodeAddr: nodeAddr,
		HostUser: "factoryuser",
	}

	// Test CreateSession
	sshUser, err := suite.sm.CreateSession(session)
	suite.NoError(err)
	suite.Equal(sessionID, sshUser) // Consul mode returns just session ID

	// Test ResolveSSHUser - should validate session existence
	ss, err := suite.sm.GetSession(sessionID)
	suite.NoError(err)
	suite.Equal(sessionID, ss.ID)
	suite.Equal(nodeAddr, ss.NodeAddr)

	// Cleanup
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)
}

func (suite *ConsulModeTestSuite) TestResolveSSHUserValidation() {
	// Consul mode should validate session existence
	sessionID := "nonexistent-session"

	// Try to resolve non-existent session
	_, _, err := suite.sm.ResolveSSHUser(sessionID)
	suite.Error(err, "Should fail for non-existent session in consul mode")

	// Create the session and try again
	session := &Session{
		ID:       sessionID,
		NodeAddr: "192.168.1.100:2222",
	}
	_, err = suite.sm.CreateSession(session)
	suite.NoError(err)

	// Now it should work
	resolvedSessionID, resolvedNodeAddr, err := suite.sm.ResolveSSHUser(sessionID)
	suite.NoError(err)
	suite.Equal(sessionID, resolvedSessionID)
	suite.Equal(session.NodeAddr, resolvedNodeAddr)

	// Clean up
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)
}

// isConsulAvailable checks if Consul is running and accessible.
// It first checks the CONSUL_ADDR environment variable, falling back to localhost:8500.
// This allows tests to run against a custom Consul instance or skip if unavailable.
func (suite *ConsulModeTestSuite) isConsulAvailable() bool {
	client, err := suite.consulClient()
	if err != nil {
		return false
	}

	// Try to get leader - simple health check
	_, err = client.Status().Leader()
	return err == nil
}

func (suite *ConsulModeTestSuite) consulAddr() string {
	addr := os.Getenv("CONSUL_ADDR")
	if addr == "" {
		addr = "localhost:8500"
	}
	return addr
}

func (suite *ConsulModeTestSuite) consulClient() (*api.Client, error) {
	config := api.DefaultConfig()
	config.Address = suite.consulAddr()

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// Test suite runners
func TestEmbeddedModeTestSuite(t *testing.T) {
	suite.Run(t, new(EmbeddedModeTestSuite))
}

func TestConsulModeTestSuite(t *testing.T) {
	suite.Run(t, new(ConsulModeTestSuite))
}
