package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/owenthereal/upterm/internal/logging"
	"github.com/owenthereal/upterm/internal/testhelpers"
	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var (
	// Shared debug logger for session tests
	sessionTestLogger = logging.Must(logging.Console(), logging.Debug()).Logger
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
	logger *slog.Logger
}

func (suite *EmbeddedSessionManagerTestSuite) SetupTest() {
	suite.logger = sessionTestLogger
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

	sm, err := newConsulSessionManager(consulURL, 5*time.Minute, sessionTestLogger)
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
	logger *slog.Logger
}

func (suite *MemoryStoreTestSuite) SetupTest() {
	suite.logger = sessionTestLogger
	suite.store = newMemorySessionStore(suite.logger)
}

func (suite *MemoryStoreTestSuite) TestStoreOperations() {
	sessionID := "test-memory-session"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "127.0.0.1:2222",
	}

	// Test Store
	reg, err := suite.store.Register(context.Background(), session)
	suite.NoError(err)

	// The same registration again is refused; only its owner's rebuild
	// stores it again.
	_, err = suite.store.Register(context.Background(), session)
	suite.ErrorIs(err, ErrSuperseded)
	_, err = suite.store.Reregister(context.Background(), reg)
	suite.NoError(err)

	// Test Get
	retrievedSession, err := suite.store.Get(sessionID)
	suite.NoError(err)
	suite.Equal(session.ID, retrievedSession.ID)
	suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)

	// Another node can't take over the same generation: the entry stays.
	moved := &Session{ID: sessionID, NodeAddr: "192.168.1.100:2222"}
	_, err = suite.store.Register(context.Background(), moved)
	suite.ErrorIs(err, ErrSuperseded)

	retrievedSession, err = suite.store.Get(sessionID)
	suite.NoError(err)
	suite.Equal("127.0.0.1:2222", retrievedSession.NodeAddr)

	// Once the entry is gone, the other node can register the ID.
	err = suite.store.Delete(sessionID)
	suite.NoError(err)
	_, err = suite.store.Register(context.Background(), moved)
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
		_, err := suite.store.Register(context.Background(), session)
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

func (suite *MemoryStoreTestSuite) TestRegisterOrderingAndConditionalRelease() {
	ctx := context.Background()
	gen1, err := suite.store.Register(ctx, &Session{ID: "o", NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	gen2, err := suite.store.Register(ctx, &Session{ID: "o", NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	_, err = suite.store.Register(ctx, &Session{ID: "o", NodeAddr: "a:22", Generation: 1})
	suite.ErrorIs(err, ErrSuperseded)
	_, err = suite.store.Register(ctx, &Session{ID: "o", NodeAddr: "a:22", Generation: 2})
	suite.ErrorIs(err, ErrSuperseded, "the same generation from another node")
	_, err = suite.store.Register(ctx, &Session{ID: "o", NodeAddr: "b:22", Generation: 2})
	suite.ErrorIs(err, ErrSuperseded, "the same generation afresh, from its own node")
	_, err = suite.store.Reregister(ctx, &Registration{Session: &Session{ID: "o", NodeAddr: "a:22", Generation: 2}})
	suite.ErrorIs(err, ErrSuperseded, "a rebuild of the same generation from another node")
	_, err = suite.store.Reregister(ctx, gen2)
	suite.NoError(err, "the owner rebuilding its own claim")
	suite.ErrorIs(suite.store.Renew(ctx, gen1), ErrLeaseLost)
	suite.NoError(suite.store.Release(ctx, gen1))
	_, err = suite.store.Get("o")
	suite.NoError(err, "a superseded release leaves its successor")
	suite.NoError(suite.store.Release(ctx, gen2))
	_, err = suite.store.Get("o")
	suite.Error(err)
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
	store1, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
	suite.Require().NoError(err)
	suite.store1 = store1

	store2, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
	suite.Require().NoError(err)
	suite.store2 = store2

	// Setup client for cleanup
	client, err := testhelpers.ConsulClient()
	suite.Require().NoError(err)
	suite.client = client
}

func (suite *ConsulStoreTestSuite) TearDownSuite() {
	if suite.store1 != nil {
		_ = suite.store1.Close()
	}
	if suite.store2 != nil {
		_ = suite.store2.Close()
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
	_, err := suite.store1.Register(context.Background(), session)
	suite.NoError(err)

	// Test Get - should be immediately available (strong consistency)
	retrievedSession, err := suite.store1.Get(sessionID)
	suite.NoError(err)
	suite.Equal(session.ID, retrievedSession.ID)
	suite.Equal(session.NodeAddr, retrievedSession.NodeAddr)
	suite.Equal(session.HostUser, retrievedSession.HostUser)

	// Test Update (requires delete first: the same generation from another node doesn't supersede it)
	err = suite.store1.Delete(sessionID)
	suite.NoError(err)

	// Verify deletion with eventual consistency (Consul may take a moment to propagate)
	suite.EventuallyWithT(func(t *assert.CollectT) {
		_, err = suite.store1.Get(sessionID)
		assert.Error(t, err, "session should be deleted")
	}, 2*time.Second, 50*time.Millisecond)

	session.NodeAddr = "192.168.1.100:2222"
	_, err = suite.store1.Register(context.Background(), session)
	suite.NoError(err)

	// Should be immediately available (strong consistency)
	retrievedSession, err = suite.store1.Get(sessionID)
	suite.NoError(err)
	suite.Equal("192.168.1.100:2222", retrievedSession.NodeAddr)

	// Test Delete
	err = suite.store1.Delete(sessionID)
	suite.NoError(err)

	// Verify deletion with eventual consistency (Consul may take a moment to propagate)
	suite.EventuallyWithT(func(t *assert.CollectT) {
		_, err = suite.store1.Get(sessionID)
		assert.Error(t, err, "session should be deleted")
	}, 2*time.Second, 50*time.Millisecond)
}

func (suite *ConsulStoreTestSuite) TestReplicationViaCacheAndWatch() {
	sessionID := "replication-test"
	session := &Session{
		ID:       sessionID,
		NodeAddr: "192.168.1.100:2222",
		HostUser: "testuser",
	}

	// Store session in store1
	_, err := suite.store1.Register(context.Background(), session)
	suite.NoError(err)
	defer func() {
		_ = suite.store1.Delete(sessionID)
	}()

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
	_, err := suite.store1.Register(context.Background(), session)
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
		_, err := suite.store1.Register(context.Background(), session)
		suite.NoError(err)
	}
	defer func() {
		for _, session := range sessions {
			_ = suite.store1.Delete(session.ID)
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

// consulGet reads an entry past both caches.
func (suite *ConsulStoreTestSuite) consulGet(id string) (*api.KVPair, *Session) {
	pair, _, err := suite.client.KV().Get(suite.store1.SessionKey(id), nil)
	suite.Require().NoError(err)
	if pair == nil {
		return nil, nil
	}
	var s Session
	suite.Require().NoError(json.Unmarshal(pair.Value, &s))
	return pair, &s
}

func (suite *ConsulStoreTestSuite) uniq(p string) string {
	return fmt.Sprintf("%s-%d", p, time.Now().UnixNano())
}

func (suite *ConsulStoreTestSuite) TestTakeoverMovesTheLease() {
	ctx, id := context.Background(), suite.uniq("takeover")
	reg1, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	reg2, err := suite.store2.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = suite.store2.Release(ctx, reg2) }()
	pair, _ := suite.consulGet(id)
	suite.Equal(reg2.lease, pair.Session, "held by the new owner's lease")
	suite.Equal(pair.ModifyIndex, reg2.index, "the handle records the index it wrote")
	suite.Require().NoError(suite.store1.Release(ctx, reg1))
	pair, s := suite.consulGet(id)
	suite.Require().NotNil(pair, "the old lease's destroy must not delete the taken-over entry")
	suite.Equal(uint64(2), s.Generation)
	_, err = suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.ErrorIs(err, ErrSuperseded)
}

func (suite *ConsulStoreTestSuite) TestRenewOfALostLeaseAndLockDelay() {
	ctx, id := context.Background(), suite.uniq("lost")
	reg, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	se, _, err := suite.client.Session().Info(reg.lease, nil)
	suite.Require().NoError(err)
	suite.Equal(time.Millisecond, se.LockDelay)
	suite.NoError(suite.store1.Renew(ctx, reg))
	_, err = suite.client.Session().Destroy(reg.lease, nil)
	suite.Require().NoError(err)
	suite.ErrorIs(suite.store1.Renew(ctx, reg), ErrLeaseLost)
}

// A fresh registration of the generation already stored is refused, even from
// the node that stored it. Only the owner's rebuild of that same registration
// takes the entry, under a lease of its own.
func (suite *ConsulStoreTestSuite) TestOnlyTheOwnersRebuildRestoresTheSameGeneration() {
	ctx, id := context.Background(), suite.uniq("same-generation")
	reg, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	_, err = suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.ErrorIs(err, ErrSuperseded)
	pair, _ := suite.consulGet(id)
	suite.Require().NotNil(pair)
	suite.Equal(reg.lease, pair.Session, "the refused registration took the entry")

	rebuilt, err := suite.store1.Reregister(ctx, reg)
	suite.Require().NoError(err)
	defer func() { _ = suite.store1.Release(ctx, rebuilt) }()
	suite.True(rebuilt.Same(reg))
	suite.NotEqual(reg.lease, rebuilt.lease)
	pair, _ = suite.consulGet(id)
	suite.Require().NotNil(pair)
	suite.Equal(rebuilt.lease, pair.Session, "the rebuild didn't take the entry")
	suite.NoError(suite.store1.Release(ctx, reg))
	pair, _ = suite.consulGet(id)
	suite.NotNil(pair, "releasing the replaced lease deleted the rebuilt entry")
}

// An entry that doesn't parse ranks as generation 0: a proven registration
// takes it over, a legacy one can't.
func (suite *ConsulStoreTestSuite) TestUnreadableEntryRanksAsGenerationZero() {
	ctx, id := context.Background(), suite.uniq("junk")
	_, err := suite.client.KV().Put(&api.KVPair{Key: suite.store1.SessionKey(id), Value: []byte("not json")}, nil)
	suite.Require().NoError(err)
	_, err = suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22"})
	suite.ErrorIs(err, ErrSuperseded)
	reg, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	suite.NoError(suite.store1.Release(ctx, reg))
}

// Shutdown cleanup from a stale listing leaves an entry another lease took
// over, and skips one that is already gone.
func (suite *ConsulStoreTestSuite) TestBatchDeleteSkipsEntriesItNoLongerHolds() {
	ctx, a, b, c := context.Background(), suite.uniq("batch-a"), suite.uniq("batch-b"), suite.uniq("batch-c")
	_, err := suite.store1.Register(ctx, &Session{ID: a, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	_, err = suite.store1.Register(ctx, &Session{ID: b, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	regB, err := suite.store2.Register(ctx, &Session{ID: b, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = suite.store2.Release(ctx, regB) }()
	regC, err := suite.store1.Register(ctx, &Session{ID: c, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	_, err = suite.client.Session().Destroy(regC.lease, nil) // the entry goes with its lease
	suite.Require().NoError(err)
	suite.Require().NoError(suite.store1.BatchDelete([]string{a, b, c}))
	pair, _ := suite.consulGet(a)
	suite.Nil(pair)
	pair, _ = suite.consulGet(b)
	suite.NotNil(pair, "taken over after the listing: survives")
}

// An ID this instance holds under two leases, as after a takeover on this
// node whose old registration isn't released yet: shutdown tries both, the
// one that holds the entry deletes it, and the other is no error, whichever
// is tried first.
func (suite *ConsulStoreTestSuite) TestBatchDeleteTriesEveryLeaseItHolds() {
	ctx := context.Background()
	var ids []string
	holderFirst, holderSecond := false, false
	for i := 0; i < 32 && (!holderFirst || !holderSecond); i++ {
		id := suite.uniq("batch-two-leases")
		reg1, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
		suite.Require().NoError(err)
		defer func() { _ = suite.store1.Release(ctx, reg1) }()
		reg2, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 2})
		suite.Require().NoError(err)
		defer func() { _ = suite.store1.Release(ctx, reg2) }()
		suite.Require().True(holdsLease(suite.store1, id, reg1.lease))
		suite.Require().True(holdsLease(suite.store1, id, reg2.lease))
		// Leases are tried in sorted order; reg2's holds the entry.
		if reg2.lease < reg1.lease {
			holderFirst = true
		} else {
			holderSecond = true
		}
		ids = append(ids, id)
	}
	suite.Require().True(holderFirst && holderSecond, "never got both orders of the two leases")

	suite.Require().NoError(suite.store1.BatchDelete(ids))
	for _, id := range ids {
		pair, _ := suite.consulGet(id)
		suite.Nil(pair, "shutdown left an entry behind")
	}
}

// txnRollback answers every transaction with a rollback naming errs, and
// passes all other requests to Consul.
type txnRollback struct {
	errs string // the JSON of the rollback's Errors
	next http.RoundTripper
}

func (t txnRollback) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/v1/txn" {
		return t.next.RoundTrip(r)
	}
	return &http.Response{
		StatusCode: http.StatusConflict,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"Errors":` + t.errs + `}`)),
		Request:    r,
	}, nil
}

// Only a lost hold lets BatchDelete skip an entry. Any other failure, such as
// a permission denial, is an error, and must never read as nothing left to
// delete; nor may a rollback that names nothing it can drop be retried
// forever.
func (suite *ConsulStoreTestSuite) TestBatchDeleteReportsOtherFailures() {
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)
	for name, errs := range map[string]string{
		"a denied delete":           `[{"OpIndex":1,"What":"Permission denied"}]`,
		"a denied session check":    `[{"OpIndex":0,"What":"Permission denied"}]`,
		"no operation named":        `[]`,
		"an operation out of range": `[{"OpIndex":8,"What":"failed session check"}]`,
	} {
		suite.Run(name, func() {
			store, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
			suite.Require().NoError(err)
			defer func() { _ = store.Close() }()
			ctx := context.Background()
			reg, err := store.Register(ctx, &Session{ID: suite.uniq("batch-fail"), NodeAddr: "a:22", Generation: 1})
			suite.Require().NoError(err)
			defer func() { _ = store.Release(ctx, reg) }()

			cfg := api.DefaultConfig()
			cfg.Address, cfg.Scheme = consulURL.Host, consulURL.Scheme
			cfg.HttpClient = &http.Client{Timeout: DefaultConsulTimeout, Transport: txnRollback{errs: errs, next: http.DefaultTransport}}
			store.client, err = api.NewClient(cfg)
			suite.Require().NoError(err)

			done := make(chan error, 1)
			go func() { done <- store.BatchDelete([]string{reg.ID()}) }()
			select {
			case err := <-done:
				suite.Error(err)
			case <-time.After(5 * time.Second):
				suite.Fail("BatchDelete kept retrying a rollback it can't make progress on")
			}
			pair, _ := suite.consulGet(reg.ID())
			suite.NotNil(pair, "the entry is still held")
		})
	}
}

func (suite *ConsulStoreTestSuite) TestRegisterHonoursItsContext() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := suite.store1.Register(ctx, &Session{ID: suite.uniq("cancelled"), NodeAddr: "a:22", Generation: 1})
	suite.ErrorIs(err, context.Canceled)
}

// firstSend records when each Consul endpoint was first sent a request.
type firstSend struct {
	mu   sync.Mutex
	at   map[string]time.Time
	next http.RoundTripper
}

func (f *firstSend) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	if _, ok := f.at[r.URL.Path]; !ok {
		f.at[r.URL.Path] = time.Now()
	}
	f.mu.Unlock()
	return f.next.RoundTrip(r)
}

// The lease's TTL clock starts when Consul creates its lock session, so the
// expiry budget must start no later than that request was sent.
func (suite *ConsulStoreTestSuite) TestConfirmedAtIsTheLeaseCreationSendTime() {
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)
	store, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
	suite.Require().NoError(err)
	defer func() { _ = store.Close() }()

	sends := &firstSend{at: make(map[string]time.Time), next: http.DefaultTransport}
	cfg := api.DefaultConfig()
	cfg.Address, cfg.Scheme = consulURL.Host, consulURL.Scheme
	cfg.HttpClient = &http.Client{Transport: sends}
	store.client, err = api.NewClient(cfg)
	suite.Require().NoError(err)

	ctx := context.Background()
	reg, err := store.Register(ctx, &Session{ID: suite.uniq("confirmed"), NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	defer func() { _ = store.Release(ctx, reg) }()

	sends.mu.Lock()
	created, txn := sends.at["/v1/session/create"], sends.at["/v1/txn"]
	sends.mu.Unlock()
	suite.Require().False(created.IsZero(), "no lock session was created")
	suite.Require().False(txn.IsZero(), "no transaction was sent")
	suite.False(reg.ConfirmedAt.After(created), "the budget starts after the lease's TTL clock")
}

// delayedTxnReply lets Consul apply every transaction at once, but holds the
// reply to the first one until release is called. entered closes once it is
// holding that reply.
type delayedTxnReply struct {
	entered chan struct{}
	resume  chan struct{}
	delayed atomic.Bool // not a sync.Once: later transactions mustn't wait on the first
	resumed sync.Once
	next    http.RoundTripper
}

func (d *delayedTxnReply) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := d.next.RoundTrip(r)
	if err == nil && r.URL.Path == "/v1/txn" && d.delayed.CompareAndSwap(false, true) {
		close(d.entered)
		<-d.resume
	}
	return resp, err
}

func (d *delayedTxnReply) release() { d.resumed.Do(func() { close(d.resume) }) }

// storeWithADelayedReply is a store of its own, on the suite's key prefix,
// whose first transaction's reply arrives only once the returned delay is
// released. Its watch runs on a client of its own, and isn't delayed.
func (suite *ConsulStoreTestSuite) storeWithADelayedReply() (*consulSessionStore, *delayedTxnReply) {
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)
	store, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
	suite.Require().NoError(err)
	delay := &delayedTxnReply{entered: make(chan struct{}), resume: make(chan struct{}), next: http.DefaultTransport}
	cfg := api.DefaultConfig()
	cfg.Address, cfg.Scheme = consulURL.Host, consulURL.Scheme
	cfg.HttpClient = &http.Client{Transport: delay}
	store.client, err = api.NewClient(cfg)
	suite.Require().NoError(err)
	return store, delay
}

type registered struct {
	reg *Registration
	err error
}

// registerDelayed registers s on store, whose reply delay holds, and returns
// once Consul has applied it; the reply arrives on the channel once delay is
// released.
func (suite *ConsulStoreTestSuite) registerDelayed(store *consulSessionStore, delay *delayedTxnReply, s *Session) <-chan registered {
	done := make(chan registered, 1)
	go func() {
		reg, err := store.Register(context.Background(), s)
		done <- registered{reg, err}
	}()
	select {
	case <-delay.entered:
	case <-time.After(5 * time.Second):
		suite.FailNow("the delayed registration never committed")
	}
	return done
}

func (suite *ConsulStoreTestSuite) awaitRegistered(done <-chan registered) *Registration {
	select {
	case r := <-done:
		suite.Require().NoError(r.err)
		return r.reg
	case <-time.After(5 * time.Second):
		suite.FailNow("the delayed registration never returned")
		return nil
	}
}

// cachedGeneration is the generation store's cache holds for id; 0 if none.
func cachedGeneration(store *consulSessionStore, id string) uint64 {
	if s, ok := store.cache.Get(id); ok {
		return s.Generation
	}
	return 0
}

// holdsLease reports whether store tracks lease as one it holds id under.
func holdsLease(store *consulSessionStore, id, lease string) bool {
	store.heldMu.Lock()
	defer store.heldMu.Unlock()
	_, ok := store.held[id][lease]
	return ok
}

// A registration's reply can arrive after a later registration of the same ID
// has committed and been recorded on the same store. Recording the earlier one
// then would make its release forget the later one's hold, and shutdown would
// leave the later one's entry behind.
func (suite *ConsulStoreTestSuite) TestALateReplyLeavesTheNewerHoldInPlace() {
	store, delay := suite.storeWithADelayedReply()
	defer func() { _ = store.Close() }()
	defer delay.release()
	ctx, id := context.Background(), suite.uniq("late-reply")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	reg2, err := store.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = store.Release(ctx, reg2) }()
	delay.release()
	reg1 := suite.awaitRegistered(first)

	suite.Equal(uint64(2), cachedGeneration(store, id), "the late reply replaced the newer registration in the cache")
	// The node refuses the older registration when it adopts, and releases it.
	suite.Require().NoError(store.Release(ctx, reg1))
	suite.True(holdsLease(store, id, reg2.lease), "the older registration's release forgot the newer one's hold")
	suite.Require().NoError(store.BatchDelete([]string{id}))
	pair, _ := suite.consulGet(id)
	suite.Nil(pair, "shutdown left the newer registration's entry behind")
}

// Likewise when the newer registration is another node's, which this store
// learned of from its watch: a late reply mustn't put the older registration
// back in the cache, where no later watch delivery would correct it, and guests
// would be routed to a superseded node.
func (suite *ConsulStoreTestSuite) TestALateReplyLeavesAnotherNodesNewerEntryCached() {
	store, delay := suite.storeWithADelayedReply()
	defer func() { _ = store.Close() }()
	defer delay.release()
	ctx, id := context.Background(), suite.uniq("late-reply-other-node")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	reg2, err := suite.store2.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = suite.store2.Release(ctx, reg2) }()
	suite.Require().Eventually(func() bool { return cachedGeneration(store, id) == 2 },
		2*time.Second, 10*time.Millisecond, "the watch never delivered generation 2")
	delay.release()
	reg1 := suite.awaitRegistered(first)

	suite.Equal(uint64(2), cachedGeneration(store, id), "the late reply replaced the newer registration in the cache")
	// The older registration ends.
	suite.Require().NoError(store.Release(ctx, reg1))
	suite.Equal(uint64(2), cachedGeneration(store, id), "the older registration's release dropped the newer entry from the cache")
	suite.False(holdsLease(store, id, reg1.lease), "the older registration is still recorded as held")
	pair, _ := suite.consulGet(id)
	suite.Require().NotNil(pair)
	suite.Equal(reg2.lease, pair.Session)
}

// End to end: a registration whose reply arrives after the watch delivered an
// index drop isn't cached, since its index doesn't order against the new
// ones. Get still finds it, in Consul.
func (suite *ConsulStoreTestSuite) TestALateReplyFromBeforeAnIndexDropIsNotCached() {
	store, delay := suite.storeWithADelayedReply()
	defer func() { _ = store.Close() }()
	defer delay.release()
	ctx, id := context.Background(), suite.uniq("late-reply-index-drop")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	// Let the watch deliver the committed entry, then stop it, so the only
	// thing that can cache the entry again is the late reply: other tests,
	// and other packages' tests, write under the same prefix, and any
	// delivery would cache it legitimately.
	suite.Require().Eventually(func() bool { return store.HasInCache(id) },
		2*time.Second, 10*time.Millisecond, "the watch never delivered the entry")
	store.watchPlan.Stop()
	// The watch's index drops, as it does when the entry with the highest
	// index goes, or after a restore.
	store.updateSessionReplica(1, nil)
	delay.release()
	reg1 := suite.awaitRegistered(first)
	defer func() { _ = store.Release(ctx, reg1) }()

	suite.False(store.HasInCache(id), "a reply from before the index drop was cached")
	s, err := store.Get(id)
	suite.Require().NoError(err, "the entry Consul holds wasn't found")
	suite.Equal(uint64(1), s.Generation)
}

// A takeover from another node moves the entry to that node's lock session
// and leaves this one's alive, so a renewal that succeeds says nothing about
// the entry. Renew reports the loss when the entry is held by another lock
// session, or gone.
func (suite *ConsulStoreTestSuite) TestRenewReportsAnEntryItNoLongerHolds() {
	ctx, id := context.Background(), suite.uniq("renew-taken-over")
	reg1, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	defer func() { _ = suite.store1.Release(ctx, reg1) }()
	reg2, err := suite.store2.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = suite.store2.Release(ctx, reg2) }()
	se, _, err := suite.client.Session().Info(reg1.lease, nil)
	suite.Require().NoError(err)
	suite.Require().NotNil(se, "the taken-over lock session is gone")
	suite.ErrorIs(suite.store1.Renew(ctx, reg1), ErrLeaseLost, "taken over by another lock session")
	suite.NoError(suite.store2.Renew(ctx, reg2))

	gone, err := suite.store1.Register(ctx, &Session{ID: suite.uniq("renew-gone"), NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	defer func() { _ = suite.store1.Release(ctx, gone) }()
	_, err = suite.client.KV().Delete(suite.store1.SessionKey(gone.ID()), nil)
	suite.Require().NoError(err)
	suite.ErrorIs(suite.store1.Renew(ctx, gone), ErrLeaseLost, "the entry is gone")
}

// lostTxnReply lets Consul apply every transaction, but loses the reply to the
// first one, as a client timeout or a failure after the write would.
type lostTxnReply struct {
	lost atomic.Bool
	next http.RoundTripper
}

func (l *lostTxnReply) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := l.next.RoundTrip(r)
	if err == nil && r.URL.Path == "/v1/txn" && l.lost.CompareAndSwap(false, true) {
		_ = resp.Body.Close()
		return nil, errors.New("reply lost")
	}
	return resp, err
}

// A registration whose transaction committed but whose reply was lost finds
// its own entry when it retries. That is its own write, not a registration to
// order it against: it succeeds, and the entry stays under its lease.
func (suite *ConsulStoreTestSuite) TestALostReplyToACommittedRegistrationStillSucceeds() {
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)
	for _, gen := range []uint64{0, 1} {
		suite.Run(fmt.Sprintf("generation %d", gen), func() {
			store, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
			suite.Require().NoError(err)
			defer func() { _ = store.Close() }()
			lost := &lostTxnReply{next: http.DefaultTransport}
			cfg := api.DefaultConfig()
			cfg.Address, cfg.Scheme = consulURL.Host, consulURL.Scheme
			cfg.HttpClient = &http.Client{Timeout: DefaultConsulTimeout, Transport: lost}
			store.client, err = api.NewClient(cfg)
			suite.Require().NoError(err)

			ctx := context.Background()
			reg, err := store.Register(ctx, &Session{ID: suite.uniq("lost-reply"), NodeAddr: "a:22", Generation: gen})
			suite.Require().True(lost.lost.Load(), "no transaction reply was lost")
			suite.Require().NoError(err)
			defer func() { _ = store.Release(ctx, reg) }()
			pair, _ := suite.consulGet(reg.ID())
			suite.Require().NotNil(pair, "the committed entry was deleted")
			suite.Equal(reg.lease, pair.Session)
			suite.Equal(pair.ModifyIndex, reg.index)
		})
	}
}

// And when the newer registration has come and gone, and the watch has
// delivered the removal: with no cached entry to compare against, a late reply
// mustn't cache the older registration either. On a quiet relay the next watch
// delivery could be a long way off, and guests would be routed to it until
// then.
func (suite *ConsulStoreTestSuite) TestALateReplyDoesNotRestoreARemovedEntry() {
	store, delay := suite.storeWithADelayedReply()
	defer func() { _ = store.Close() }()
	defer delay.release()
	ctx, id := context.Background(), suite.uniq("late-reply-removed")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	reg2, err := suite.store2.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	suite.Require().Eventually(func() bool { return cachedGeneration(store, id) == 2 },
		2*time.Second, 10*time.Millisecond, "the watch never delivered generation 2")
	suite.Require().NoError(suite.store2.Release(ctx, reg2))
	suite.Require().Eventually(func() bool { return !store.HasInCache(id) },
		2*time.Second, 10*time.Millisecond, "the watch never delivered the removal")
	delay.release()
	reg1 := suite.awaitRegistered(first)
	defer func() { _ = store.Release(ctx, reg1) }()

	suite.False(store.HasInCache(id), "the late reply cached a registration that was superseded and removed")
	_, err = store.Get(id)
	suite.Error(err, "a removed registration is still found")
}

// Without renewal, Consul expires an entry within twice its TTL, which is at
// least 10 s.
func (suite *ConsulStoreTestSuite) TestLeaseExpiryAndRenewal() {
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	suite.Require().NoError(err)
	short, err := newConsulSessionStore(consulURL, 10*time.Second, sessionTestLogger)
	suite.Require().NoError(err)
	defer func() { _ = short.Close() }()
	ctx := context.Background()
	unrenewed, err := short.Register(ctx, &Session{ID: suite.uniq("unrenewed"), NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	renewed, err := short.Register(ctx, &Session{ID: suite.uniq("renewed"), NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	defer func() { _ = short.Release(ctx, renewed) }()
	for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		suite.Require().NoError(short.Renew(ctx, renewed))
	}
	pair, _ := suite.consulGet(unrenewed.ID())
	suite.Nil(pair)
	pair, _ = suite.consulGet(renewed.ID())
	suite.NotNil(pair)
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

// The cache takes writes in whatever order they reach it, and keeps the
// latest. A watch snapshot older than a write made here leaves that write in
// place, and one that has caught up with it decides, including by leaving it
// out. A release removes only an entry its own lease holds.
func TestSessionCacheKeepsTheLatestWrite(t *testing.T) {
	c := newSessionCache(sessionTestLogger)
	gen := func() uint64 {
		if s, ok := c.Get("id"); ok {
			return s.Generation
		}
		return 0
	}
	entry := func(gen, index uint64) cachedSession {
		return cachedSession{session: &Session{ID: "id", Generation: gen}, index: index, lease: fmt.Sprintf("lease-%d", gen)}
	}
	set := func(gen, index uint64) { c.Set("id", entry(gen, index), c.Epoch()) }
	snapshot := func(gen, index uint64) map[string]cachedSession {
		return map[string]cachedSession{"id": entry(gen, index)}
	}

	set(2, 20)
	set(1, 10)
	assert.Equal(t, uint64(2), gen(), "an earlier write replaced a later one")

	c.ReplaceAll(15, snapshot(1, 10))
	assert.Equal(t, uint64(2), gen(), "a snapshot from before the write undid it")
	c.ReplaceAll(19, map[string]cachedSession{})
	assert.Equal(t, uint64(2), gen(), "a snapshot from before the write removed it")
	c.ReplaceAll(25, snapshot(3, 25))
	assert.Equal(t, uint64(3), gen(), "a snapshot past the write didn't replace it")

	c.Delete("id", "lease-2")
	assert.Equal(t, uint64(3), gen(), "releasing a lease removed an entry another lease holds")
	c.Delete("id", "lease-3")
	assert.Zero(t, gen())

	set(3, 28)
	c.ReplaceAll(30, map[string]cachedSession{})
	assert.Zero(t, gen(), "a snapshot past the write kept an entry it no longer has")

	// With nothing cached, a write the last snapshot covered and left out was
	// removed or superseded by then; one past it is new.
	set(3, 30)
	assert.Zero(t, gen(), "a write the watch saw removed came back")
	set(4, 31)
	assert.Equal(t, uint64(4), gen(), "a write past the last snapshot was dropped")
}

// When the watch's index drops, nothing cached from before the drop outranks
// the snapshot that shows it, and writes begun after it are taken, for IDs
// cached before it too.
func TestSessionCacheTakesTheSnapshotWholeAfterAnIndexDrop(t *testing.T) {
	c := newSessionCache(sessionTestLogger)
	entry := func(gen, index uint64) cachedSession {
		return cachedSession{session: &Session{Generation: gen}, index: index}
	}
	gen := func(id string) uint64 {
		if s, ok := c.Get(id); ok {
			return s.Generation
		}
		return 0
	}

	c.ReplaceAll(100, map[string]cachedSession{"old": entry(1, 90)})
	c.Set("local", entry(1, 101), c.Epoch()) // written past the last snapshot
	c.ReplaceAll(5, map[string]cachedSession{"new": entry(1, 4)})
	assert.False(t, c.Has("old"), "an entry from before the drop survived it")
	assert.False(t, c.Has("local"), "a write from before the drop survived it")
	assert.Equal(t, uint64(1), gen("new"))

	c.Set("old", entry(2, 6), c.Epoch())
	assert.Equal(t, uint64(2), gen("old"), "a write after the drop was refused")
	c.Set("again", entry(1, 5), c.Epoch())
	assert.Zero(t, gen("again"), "the dropped snapshot's index isn't the floor")
}

// fakeConsul answers the calls a store makes for a single session entry. Its
// first write is at index 100 and every later one at 6, as when Consul's index
// goes backwards between them; reset loses the entry, as a restore can.
type fakeConsul struct {
	*httptest.Server
	mu     sync.Mutex
	pair   *api.KVPair
	leases int
	writes int
}

func newFakeConsul(t *testing.T) *fakeConsul {
	f := &fakeConsul{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/session/create":
			f.leases++
			_ = json.NewEncoder(w).Encode(map[string]string{"ID": fmt.Sprintf("lease-%d", f.leases)})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/kv/"):
			if f.pair == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(api.KVPairs{f.pair})
		case r.URL.Path == "/v1/txn":
			var ops api.TxnOps
			if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			last := ops[len(ops)-1].KV
			if last.Verb == api.KVDelete {
				f.pair = nil
				_ = json.NewEncoder(w).Encode(api.TxnResponse{})
				return
			}
			f.writes++
			index := uint64(100)
			if f.writes > 1 {
				index = 6
			}
			f.pair = &api.KVPair{Key: last.Key, Value: last.Value, Session: last.Session, ModifyIndex: index}
			_ = json.NewEncoder(w).Encode(api.TxnResponse{Results: api.TxnResults{&api.TxnResult{KV: f.pair}}})
		case strings.HasPrefix(r.URL.Path, "/v1/session/destroy/"):
			if f.pair != nil && f.pair.Session == strings.TrimPrefix(r.URL.Path, "/v1/session/destroy/") {
				f.pair = nil
			}
			_, _ = w.Write([]byte("true"))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeConsul) entry() *api.KVPair {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pair
}

func (f *fakeConsul) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pair = nil
}

// newFakeConsulStore is a store on f with no watch running; tests deliver
// what the watch would.
func newFakeConsulStore(t *testing.T, f *fakeConsul) *consulSessionStore {
	cfg := api.DefaultConfig()
	cfg.Address = f.URL
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)
	return &consulSessionStore{client: client, logger: logger, ttl: time.Minute, keyPrefix: "fake",
		cache: newSessionCache(logger), held: make(map[string]map[string]struct{})}
}

// Consul's index can go backwards, so what this instance holds can't be
// ordered by it. A registration rebuilt after a drop commits at a lower index
// than the one it replaces, and must still be tracked: retiring the old lease
// leaves it, and its entry in the cache, and shutdown deletes it.
func TestARebuildAfterAnIndexDropStaysHeld(t *testing.T) {
	consul := newFakeConsul(t)
	store := newFakeConsulStore(t, consul)
	ctx := context.Background()
	original, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node", Generation: 1})
	require.NoError(t, err)
	store.updateSessionReplica(100, api.KVPairs{consul.entry()})
	consul.reset() // the entry and its lock session are lost
	store.updateSessionReplica(5, nil)
	require.False(t, store.HasInCache("id"))

	rebuilt, err := store.Reregister(ctx, original)
	require.NoError(t, err)
	require.Less(t, rebuilt.index, original.index)
	assert.True(t, holdsLease(store, "id", rebuilt.lease), "the rebuilt lease isn't tracked")
	// The lease keeper retires the old handle once the rebuild succeeds.
	require.NoError(t, store.Release(ctx, original))
	assert.True(t, holdsLease(store, "id", rebuilt.lease), "retiring the old lease dropped the rebuilt one's tracking")
	assert.True(t, store.HasInCache("id"), "retiring the old lease dropped the rebuilt entry from the cache")
	require.NoError(t, store.BatchDelete([]string{"id"}))
	assert.Nil(t, consul.entry(), "shutdown left the rebuilt registration in Consul")
}

// An index from before a drop doesn't order against one after it. A local
// write whose Consul call began before the cache saw the drop is dropped, and
// the writes and snapshots after it decide.
func TestSessionCacheDropsALocalWriteFromBeforeAnIndexDrop(t *testing.T) {
	cache := newSessionCache(sessionTestLogger)
	old := &Session{ID: "id", NodeAddr: "old-node", Generation: 1}
	current := &Session{ID: "id", NodeAddr: "new-node", Generation: 2}
	cache.ReplaceAll(100, map[string]cachedSession{"id": {session: old, index: 100, lease: "old"}})
	before := cache.Epoch()                                                        // a call begins
	cache.ReplaceAll(5, map[string]cachedSession{})                                // the index drops
	cache.Set("id", cachedSession{session: old, index: 101, lease: "old"}, before) // and its reply arrives
	cache.Set("id", cachedSession{session: current, index: 6, lease: "current"}, cache.Epoch())
	cache.ReplaceAll(6, map[string]cachedSession{"id": {session: current, index: 6, lease: "current"}})
	got, ok := cache.Get("id")
	require.True(t, ok)
	require.Equal(t, current.NodeAddr, got.NodeAddr, "a write from before the drop outranks what came after it")
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
