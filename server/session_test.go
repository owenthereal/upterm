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
// Tests are organized by layers with proper separation of concerns:
//
// SessionManager Layer (behavior tests):
// - EmbeddedSessionManagerTestSuite: Tests SessionManager with embedded routing
// - ConsulSessionManagerTestSuite: Tests SessionManager with consul routing
//
// Store Layer (implementation tests):
// - MemoryStoreTestSuite: Tests memory store operations directly
// - ConsulStoreTestSuite: Tests consul store operations and replication

//
// SessionManager Layer Tests - Focus on routing mode behavior
//

// EmbeddedSessionManagerTestSuite tests SessionManager behavior in embedded mode
type EmbeddedSessionManagerTestSuite struct {
	suite.Suite
	sm     *SessionManager
	logger logrus.FieldLogger
}

func (suite *EmbeddedSessionManagerTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.sm = newEmbeddedSessionManager(suite.logger)
}

func (suite *EmbeddedSessionManagerTestSuite) TestCreateAndResolveSession() {
	sessionID := "test-session-123"
	nodeAddr := "127.0.0.1:2222"
	session := &Session{
		ID:       sessionID,
		NodeAddr: nodeAddr,
	}

	// Test CreateSession returns encoded SSH user for embedded mode
	sshUser, err := suite.sm.CreateSession(session)
	suite.NoError(err)
	suite.Contains(sshUser, sessionID)
	suite.Contains(sshUser, ":") // embedded mode uses "sessionID:base64(nodeAddr)" format

	// Test ResolveSSHUser decodes correctly
	resolvedSessionID, resolvedNodeAddr, err := suite.sm.ResolveSSHUser(sshUser)
	suite.NoError(err)
	suite.Equal(sessionID, resolvedSessionID)
	suite.Equal(nodeAddr, resolvedNodeAddr)

	// Test GetSession retrieves the session
	retrievedSession, err := suite.sm.GetSession(sessionID)
	suite.NoError(err)
	suite.Equal(sessionID, retrievedSession.ID)
	suite.Equal(nodeAddr, retrievedSession.NodeAddr)
}

func (suite *EmbeddedSessionManagerTestSuite) TestResolveSSHUser_DoesNotValidateExistence() {
	// In embedded mode, ResolveSSHUser should not validate session existence
	// because sessions may exist on other nodes in distributed deployments
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

func (suite *EmbeddedSessionManagerTestSuite) TestResolveSSHUser_InvalidFormats() {
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

func (suite *EmbeddedSessionManagerTestSuite) TestRoutingMode() {
	suite.Equal(routing.ModeEmbedded, suite.sm.GetRoutingMode())
}

func (suite *EmbeddedSessionManagerTestSuite) TestDeleteSession() {
	sessionID := "test-delete-session"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
	}

	// Create session
	_, err := suite.sm.CreateSession(session)
	suite.NoError(err)

	// Verify it exists
	_, err = suite.sm.GetSession(sessionID)
	suite.NoError(err)

	// Delete session
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)

	// Verify it's deleted
	_, err = suite.sm.GetSession(sessionID)
	suite.Error(err)
}

// ConsulSessionManagerTestSuite tests SessionManager behavior in consul mode
type ConsulSessionManagerTestSuite struct {
	suite.Suite
	sm     *SessionManager
	client *api.Client
}

func (suite *ConsulSessionManagerTestSuite) SetupSuite() {
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

func (suite *ConsulSessionManagerTestSuite) TearDownSuite() {
	if suite.client != nil && suite.sm != nil {
		// Clean up test data using the actual key prefix from the store
		if store, ok := suite.sm.GetStore().(*consulSessionStore); ok {
			_, err := suite.client.KV().DeleteTree(store.KeyPrefix(), nil)
			suite.NoError(err)
		}
	}
}

func (suite *ConsulSessionManagerTestSuite) TestCreateAndResolveSession() {
	sessionID := fmt.Sprintf("test-consul-session-%d", time.Now().UnixNano())
	nodeAddr := "192.168.1.100:2222"
	session := &Session{
		ID:       sessionID,
		NodeAddr: nodeAddr,
		HostUser: "testuser",
	}

	// Test CreateSession returns just session ID for consul mode
	sshUser, err := suite.sm.CreateSession(session)
	suite.NoError(err)
	suite.Equal(sessionID, sshUser) // Consul mode returns just session ID

	// Test GetSession retrieves the session immediately (strong consistency)
	retrievedSession, err := suite.sm.GetSession(sessionID)
	suite.NoError(err)
	suite.NotNil(retrievedSession)
	suite.Equal(sessionID, retrievedSession.ID)
	suite.Equal(nodeAddr, retrievedSession.NodeAddr)

	// Test ResolveSSHUser validates session existence and returns session info
	resolvedSessionID, resolvedNodeAddr, err := suite.sm.ResolveSSHUser(sessionID)
	suite.NoError(err)
	suite.Equal(sessionID, resolvedSessionID)
	suite.Equal(nodeAddr, resolvedNodeAddr)

	// Cleanup
	err = suite.sm.DeleteSession(sessionID)
	suite.NoError(err)
}

func (suite *ConsulSessionManagerTestSuite) TestResolveSSHUser_ValidatesExistence() {
	// In consul mode, ResolveSSHUser should validate session existence because
	// all nodes share the same Consul store
	sessionID := fmt.Sprintf("nonexistent-session-%d", time.Now().UnixNano())

	// Try to resolve non-existent session - should fail
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

func (suite *ConsulSessionManagerTestSuite) TestRoutingMode() {
	suite.Equal(routing.ModeConsul, suite.sm.GetRoutingMode())
}

//
// Store Layer Tests - Focus on storage implementation details
//

// MemoryStoreTestSuite tests the memory store implementation directly
type MemoryStoreTestSuite struct {
	suite.Suite
	store  *memorySessionStore
	logger logrus.FieldLogger
}

func (suite *MemoryStoreTestSuite) SetupTest() {
	suite.logger = logrus.New()
	suite.store = newMemorySessionStore(suite.logger)
}

func (suite *MemoryStoreTestSuite) TestStoreOperations() {
	sessionID := "test-memory-session"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
	}

	// Test Store
	err := suite.store.Store(session)
	suite.NoError(err)

	// Test Store duplicate (should succeed - overwrites)
	err = suite.store.Store(session)
	suite.NoError(err)

	// Test Get
	retrievedSession, err := suite.store.Get(sessionID)
	suite.NoError(err)
	suite.Equal(session.ID, retrievedSession.ID)
	suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)

	// Test Update (Store is used for both create and update)
	session.NodeAddr = "192.168.1.100:2222"
	err = suite.store.Store(session)
	suite.NoError(err)

	retrievedSession, err = suite.store.Get(sessionID)
	suite.NoError(err)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)

	// Test Delete
	err = suite.store.Delete(sessionID)
	suite.NoError(err)

	// Verify deletion
	_, err = suite.store.Get(sessionID)
	suite.Error(err)

	// Test Delete non-existent (should succeed - idempotent)
	err = suite.store.Delete("nonexistent")
	suite.NoError(err)
}

func (suite *MemoryStoreTestSuite) TestBatchOperations() {
	sessions := []*Session{
		{ID: "batch-1", NodeAddr: "192.168.1.1:2222"},
		{ID: "batch-2", NodeAddr: "192.168.1.2:2222"},
		{ID: "batch-3", NodeAddr: "192.168.1.3:2222"},
	}

	// Store all sessions
	for _, session := range sessions {
		err := suite.store.Store(session)
		suite.NoError(err)
	}

	// Test List
	allSessions, err := suite.store.List()
	suite.NoError(err)
	suite.Len(allSessions, 3)

	// Test BatchDelete
	sessionIDs := []string{"batch-1", "batch-2", "batch-3"}
	err = suite.store.BatchDelete(sessionIDs)
	suite.NoError(err)

	// Verify all deleted
	for _, sessionID := range sessionIDs {
		_, err = suite.store.Get(sessionID)
		suite.Error(err)
	}
}

func (suite *MemoryStoreTestSuite) TestClose() {
	// Memory store Close is a no-op but should not error
	err := suite.store.Close()
	suite.NoError(err)
}

// ConsulStoreTestSuite tests the consul store implementation directly including replication
type ConsulStoreTestSuite struct {
	suite.Suite
	store1 *consulSessionStore // First store instance
	store2 *consulSessionStore // Second store instance
	client *api.Client
}

func (suite *ConsulStoreTestSuite) SetupSuite() {
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
}

func (suite *ConsulStoreTestSuite) TearDownSuite() {
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

func (suite *ConsulStoreTestSuite) TestBasicStoreOperations() {
	sessionID := fmt.Sprintf("test-consul-basic-%d", time.Now().UnixNano())
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
		HostUser: "testuser",
	}

	// Test Store
	err := suite.store1.Store(session)
	suite.NoError(err)

	// Test Get - should be immediately available (strong consistency)
	retrievedSession, err := suite.store1.Get(sessionID)
	suite.NoError(err)
	suite.Equal(session.ID, retrievedSession.ID)
	suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)
	suite.Equal(session.HostUser, retrievedSession.HostUser)

	// Test Update (requires delete first due to Consul session locking mechanism)
	err = suite.store1.Delete(sessionID)
	suite.NoError(err)

	// Should be immediately deleted (strong consistency)
	_, err = suite.store1.Get(sessionID)
	suite.Error(err)

	session.NodeAddr = "192.168.1.100:2222"
	err = suite.store1.Store(session)
	suite.NoError(err)

	// Should be immediately available (strong consistency)
	retrievedSession, err = suite.store1.Get(sessionID)
	suite.NoError(err)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)

	// Test Delete
	err = suite.store1.Delete(sessionID)
	suite.NoError(err)

	// Should be immediately deleted (strong consistency)
	_, err = suite.store1.Get(sessionID)
	suite.Error(err)
}

func (suite *ConsulStoreTestSuite) TestReplicationViaCacheAndWatch() {
	sessionID := "replication-test"
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

func (suite *ConsulStoreTestSuite) TestReplicationHandlesDeletion() {
	sessionID := "deletion-replication-test"
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

func (suite *ConsulStoreTestSuite) TestSessionNotFoundNoRetry() {
	// Test that session not found errors are not retried unnecessarily
	nonExistentSessionID := fmt.Sprintf("nonexistent-%d", time.Now().UnixNano())
	
	// This should fail quickly without retries
	start := time.Now()
	_, err := suite.store1.Get(nonExistentSessionID)
	duration := time.Since(start)
	
	suite.Error(err)
	suite.Contains(err.Error(), "not found")
	// Should fail quickly (under 100ms) since we don't retry "not found" errors
	suite.Less(duration, 100*time.Millisecond, "Session not found should fail quickly without retries")
}

func (suite *ConsulStoreTestSuite) TestBatchOperations() {
	sessions := []*Session{
		{ID: "batch-consul-1", NodeAddr: "192.168.1.1:2222", HostUser: "user1"},
		{ID: "batch-consul-2", NodeAddr: "192.168.1.2:2222", HostUser: "user2"},
		{ID: "batch-consul-3", NodeAddr: "192.168.1.3:2222", HostUser: "user3"},
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

	// Test List operation
	allSessions, err := suite.store1.List()
	suite.NoError(err)
	suite.GreaterOrEqual(len(allSessions), 3) // May have other sessions from parallel tests

	// Test BatchDelete
	sessionIDs := []string{"batch-consul-1", "batch-consul-2", "batch-consul-3"}
	err = suite.store1.BatchDelete(sessionIDs)
	suite.NoError(err)

	// Verify all sessions are deleted
	for _, sessionID := range sessionIDs {
		_, err = suite.store1.Get(sessionID)
		suite.Error(err)
	}
}

// Helper methods for replication testing
func (suite *ConsulStoreTestSuite) waitForSessionInCache(sessionID string) {
	suite.EventuallyWithT(func(t *assert.CollectT) {
		assert := assert.New(t)
		assert.True(suite.store2.HasInCache(sessionID), "Session should be in store2's cache via watch")
	}, 2*time.Second, 10*time.Millisecond)
}

func (suite *ConsulStoreTestSuite) waitForSessionRemovedFromCache(sessionID string) {
	suite.EventuallyWithT(func(t *assert.CollectT) {
		assert := assert.New(t)
		assert.False(suite.store2.HasInCache(sessionID), "Session should be removed from store2's cache via watch")
	}, 2*time.Second, 10*time.Millisecond)
}

//
// Test Suite Runners
//

func TestEmbeddedSessionManagerTestSuite(t *testing.T) {
	suite.Run(t, new(EmbeddedSessionManagerTestSuite))
}

func TestConsulSessionManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ConsulSessionManagerTestSuite))
}

func TestMemoryStoreTestSuite(t *testing.T) {
	suite.Run(t, new(MemoryStoreTestSuite))
}

func TestConsulStoreTestSuite(t *testing.T) {
	suite.Run(t, new(ConsulStoreTestSuite))
}