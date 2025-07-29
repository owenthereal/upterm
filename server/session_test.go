package server

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
	if !testhelpers.IsConsulAvailable() {
		suite.T().Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}

	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)

	sm, err := newConsulSessionManager(consulURL, 5*time.Minute, logrus.New())
	suite.Require().NoError(err)
	suite.sm = sm

	// Setup client for cleanup
	client, err := testhelpers.ConsulClient()
	suite.Require().NoError(err)
	suite.client = client
}

func (suite *ConsulModeTestSuite) TearDownSuite() {
	if suite.client != nil {
		// Clean up test data using the actual key prefix from the store
		if store, ok := suite.sm.GetStore().(*consulSessionStore); ok {
			_, err := suite.client.KV().DeleteTree(store.KeyPrefix(), nil)
			suite.NoError(err)
		}
	}
}

func (suite *ConsulModeTestSuite) TestStoreOperations() {
	store := suite.sm.GetStore()

	sessionID := fmt.Sprintf("test-consul-session-%d", time.Now().UnixNano())
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
		HostUser: "testuser",
	}

	// Test Store
	err := store.Store(session)
	suite.NoError(err)

	// Test Get - should be immediately available (strong consistency)
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

	// Should be immediately deleted (strong consistency)
	_, err = store.Get(sessionID)
	suite.Error(err)

	session.NodeAddr = "192.168.1.100:2222"
	err = store.Store(session)
	suite.NoError(err)

	// Should be immediately available (strong consistency)
	retrievedSession, err = store.Get(sessionID)
	suite.NoError(err)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)

	// Test Delete
	err = store.Delete(sessionID)
	suite.NoError(err)

	// Should be immediately deleted (strong consistency)
	_, err = store.Get(sessionID)
	suite.Error(err)
}

func (suite *ConsulModeTestSuite) TestSessionOperations() {
	sessionID := fmt.Sprintf("test-factory-session-%d", time.Now().UnixNano())
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

	// Test GetSession - should be immediately available (strong consistency)
	ss, err := suite.sm.GetSession(sessionID)
	suite.NoError(err)
	suite.NotNil(ss)
	suite.Equal(sessionID, ss.ID)
	suite.Equal(nodeAddr, ss.NodeAddr)

	// Cleanup
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)
}

func (suite *ConsulModeTestSuite) TestResolveSSHUserValidation() {
	// Consul mode should validate session existence
	sessionID := fmt.Sprintf("nonexistent-session-%d", time.Now().UnixNano())

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

	// Now it should work immediately (strong consistency)
	resolvedSessionID, resolvedNodeAddr, err := suite.sm.ResolveSSHUser(sessionID)
	suite.NoError(err)
	suite.Equal(sessionID, resolvedSessionID)
	suite.Equal(session.NodeAddr, resolvedNodeAddr)

	// Clean up
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)
}


// Test suite runners
func TestEmbeddedModeTestSuite(t *testing.T) {
	suite.Run(t, new(EmbeddedModeTestSuite))
}

func TestConsulModeTestSuite(t *testing.T) {
	suite.Run(t, new(ConsulModeTestSuite))
}

// ConsulReplicationTestSuite tests the session replication functionality at the store level
type ConsulReplicationTestSuite struct {
	suite.Suite

	store1 *consulSessionStore // First store instance
	store2 *consulSessionStore // Second store instance
	client *api.Client
}

func (suite *ConsulReplicationTestSuite) SetupSuite() {
	// Skip if Consul is not available
	if !testhelpers.IsConsulAvailable() {
		suite.T().Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}

	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)

	// Create two store instances to simulate multi-node setup
	store1, err := newConsulSessionStore(consulURL, 5*time.Minute, logrus.New())
	suite.Require().NoError(err)
	suite.store1 = store1

	store2, err := newConsulSessionStore(consulURL, 5*time.Minute, logrus.New())
	suite.Require().NoError(err)
	suite.store2 = store2

	// Setup client for cleanup
	client, err := testhelpers.ConsulClient()
	suite.Require().NoError(err)
	suite.client = client

	// Watches will initialize automatically when first used
}

func (suite *ConsulReplicationTestSuite) TearDownSuite() {
	if suite.store1 != nil {
		suite.store1.Close()
	}
	if suite.store2 != nil {
		suite.store2.Close()
	}
	if suite.client != nil {
		// Clean up test data using the actual key prefix from the store
		_, err := suite.client.KV().DeleteTree(suite.store1.KeyPrefix(), nil)
		suite.NoError(err)
	}
}

func (suite *ConsulReplicationTestSuite) TestWatchPropagatesSessionCreation() {
	sessionID := "watch-creation-test"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "192.168.1.100:2222",
		HostUser: "testuser",
	}

	// Store session in store1
	err := suite.store1.Store(session)
	suite.NoError(err)
	defer suite.store1.Delete(sessionID)

	// Wait for watch to propagate to store2's cache
	suite.waitForSessionInCache(sessionID)

	// Verify data integrity and measure lookup performance
	start := time.Now()
	retrievedSession, err := suite.store2.Get(sessionID)
	duration := time.Since(start)

	suite.NoError(err)
	suite.Equal(sessionID, retrievedSession.ID)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)
	suite.Equal("testuser", retrievedSession.HostUser)
	suite.Less(duration, 1*time.Millisecond, "Memory lookup should be instant")
}

func (suite *ConsulReplicationTestSuite) TestWatchPropagatesSessionDeletion() {
	sessionID := "watch-deletion-test"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "172.16.0.1:2222",
		HostUser: "deleteuser",
	}

	// Store session and wait for replication
	err := suite.store1.Store(session)
	suite.NoError(err)
	suite.waitForSessionInCache(sessionID)

	// Delete from store1
	err = suite.store1.Delete(sessionID)
	suite.NoError(err)

	// Wait for deletion to propagate via watch
	suite.waitForSessionRemovedFromCache(sessionID)

	// Verify session is actually deleted
	_, err = suite.store2.Get(sessionID)
	suite.Error(err, "Session should not be accessible after deletion")
}

func (suite *ConsulReplicationTestSuite) TestWatchHandlesMultipleSessions() {
	sessions := []*Session{
		{ID: "multi-1", NodeAddr: "192.168.1.1:2222", HostUser: "user1"},
		{ID: "multi-2", NodeAddr: "192.168.1.2:2222", HostUser: "user2"},
		{ID: "multi-3", NodeAddr: "192.168.1.3:2222", HostUser: "user3"},
	}

	// Store all sessions in store1
	for _, session := range sessions {
		err := suite.store1.Store(session)
		suite.NoError(err)
	}
	defer func() {
		for _, session := range sessions {
			suite.store1.Delete(session.ID)
		}
	}()

	// Wait for all sessions to propagate via watch
	suite.EventuallyWithT(func(t *assert.CollectT) {
		assert := assert.New(t)
		for _, session := range sessions {
			assert.True(suite.store2.HasInCache(session.ID), "Session %s should be in store2's cache", session.ID)
		}
	}, 2*time.Second, 10*time.Millisecond)

	// Verify data integrity for all sessions
	for _, session := range sessions {
		retrievedSession, err := suite.store2.Get(session.ID)
		suite.NoError(err)
		suite.Equal(session.ID, retrievedSession.ID)
		suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)
		suite.Equal(session.HostUser, retrievedSession.HostUser)
	}
}

// Helper method to wait for session to appear in cache via watch
func (suite *ConsulReplicationTestSuite) waitForSessionInCache(sessionID string) {
	suite.EventuallyWithT(func(t *assert.CollectT) {
		assert := assert.New(t)
		assert.True(suite.store2.HasInCache(sessionID), "Session should be in store2's cache via watch")
	}, 2*time.Second, 10*time.Millisecond)
}

// Helper method to wait for session to be removed from cache via watch
func (suite *ConsulReplicationTestSuite) waitForSessionRemovedFromCache(sessionID string) {
	suite.EventuallyWithT(func(t *assert.CollectT) {
		assert := assert.New(t)
		assert.False(suite.store2.HasInCache(sessionID), "Session should be removed from store2's cache via watch")
	}, 2*time.Second, 10*time.Millisecond)
}


func TestConsulReplicationTestSuite(t *testing.T) {
	suite.Run(t, new(ConsulReplicationTestSuite))
}
