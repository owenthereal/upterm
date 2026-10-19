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
	"path"
	"slices"
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

// suiteConsulURL is the Consul URL with a key prefix of the suite's own, inside
// the one CONSUL_URL names. Other packages' tests share the agent and the
// default prefix, so a suite that deletes its tree when it ends must not be
// pointed at that.
func suiteConsulURL(suiteName string) (*url.URL, error) {
	consulURL, err := url.Parse(testhelpers.ConsulURL())
	if err != nil {
		return nil, err
	}
	consulURL.Path = path.Join("/", consulURL.Path, fmt.Sprintf("uptermd-test-%s-%d", suiteName, time.Now().UnixNano()))
	return consulURL, nil
}

// removeSuiteConsulData deletes what a suite wrote: its keys, and the catalog
// node its stores registered, which every store on one prefix shares. Without
// the node, each run leaves another on an agent that outlives it.
func removeSuiteConsulData(client *api.Client, store *consulSessionStore) error {
	_, err := client.KV().DeleteTree(store.KeyPrefix(), nil)
	if err != nil {
		return err
	}
	_, err = client.Catalog().Deregister(&api.CatalogDeregistration{Node: store.NodeName()}, nil)
	return err
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

	consulURL, err := suiteConsulURL("session-manager")
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
			suite.NoError(removeSuiteConsulData(suite.client, store))
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

	consulURL *url.URL // the suite's own key prefix
}

func (suite *ConsulStoreTestSuite) SetupSuite() {
	// Skip if Consul is not available
	if !testhelpers.IsConsulAvailable() {
		suite.T().Skip("Consul not available - set CONSUL_URL or ensure Consul is running on localhost:8500")
	}

	consulURL, err := suiteConsulURL("store")
	suite.Require().NoError(err)
	suite.consulURL = consulURL

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
		suite.NoError(removeSuiteConsulData(suite.client, suite.store1))
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

	t := suite.T()
	replicated := observe(t, suite.store2)

	// Store session in store1
	_, err := suite.store1.Register(context.Background(), session)
	suite.NoError(err)
	defer func() {
		_ = suite.store1.Delete(sessionID)
	}()

	// Wait for store2's watch to deliver it. The cache takes each delivery
	// before the observers see it, so the read below finds it there.
	replicated.await(t, 5*time.Second, present(sessionID, 0))
	suite.True(suite.store2.HasInCache(sessionID), "store2's cache never took the session its watch delivered")

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
	t := suite.T()
	replicated := observe(t, suite.store2)
	_, err := suite.store1.Register(context.Background(), session)
	suite.NoError(err)
	replicated.await(t, 5*time.Second, present(sessionID, 0))
	suite.True(suite.store2.HasInCache(sessionID), "store2's cache never took the session its watch delivered")

	// Delete from store1
	err = suite.store1.Delete(sessionID)
	suite.NoError(err)

	// Wait for store2's watch to deliver the deletion
	replicated.await(t, 5*time.Second, absent(sessionID))
	suite.False(suite.store2.HasInCache(sessionID), "store2's cache kept the session after its watch delivered the deletion")

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

	// Store all sessions in store1. Observe doesn't replay, so both stores'
	// observers are subscribed first: one subscribed after the registers could
	// miss the only delivery that shows them.
	t := suite.T()
	local, replicated := observe(t, suite.store1), observe(t, suite.store2)
	for _, session := range sessions {
		_, err := suite.store1.Register(context.Background(), session)
		suite.NoError(err)
	}
	defer func() {
		for _, session := range sessions {
			_ = suite.store1.Delete(session.ID)
		}
	}()

	// Wait for all sessions to propagate via watch, to store2 and to store1
	for _, session := range sessions {
		replicated.await(t, 5*time.Second, present(session.ID, 0))
		suite.True(suite.store2.HasInCache(session.ID), "store2's cache never took %s, which its watch delivered", session.ID)
		local.await(t, 5*time.Second, present(session.ID, 0))
	}

	// Test List operation
	allSessions, err := suite.store1.List()
	suite.NoError(err)
	suite.GreaterOrEqual(len(allSessions), 3) // May have other sessions from parallel tests

	// Test BatchDelete
	sessionIDs := []string{"batch-consul-1", "batch-consul-2", "batch-consul-3"}
	err = suite.store1.BatchDelete(sessionIDs)
	suite.NoError(err)

	// BatchDelete drops the entries from store1's cache, but a delivery from
	// before the delete that lands after it puts them back until the next
	// delivery. Wait for store1's watch to deliver the deletes: no later
	// delivery is from before them.
	for _, sessionID := range sessionIDs {
		local.await(t, 5*time.Second, absent(sessionID))
	}

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

// txnEntry is an entry for a test that drives Consul's transactions itself:
// its key, a value for each generation, and a lock session per holder, all
// removed at cleanup.
type txnEntry struct {
	suite *ConsulStoreTestSuite
	id    string
	key   string
}

func (suite *ConsulStoreTestSuite) txnEntry(prefix string) txnEntry {
	id := suite.uniq(prefix)
	e := txnEntry{suite: suite, id: id, key: suite.store1.SessionKey(id)}
	suite.T().Cleanup(func() { _, _ = suite.client.KV().Delete(e.key, nil) })
	return e
}

func (e txnEntry) value(gen uint64) []byte {
	b, err := json.Marshal(&Session{ID: e.id, NodeAddr: "a:22", Generation: gen})
	e.suite.Require().NoError(err)
	return b
}

func (e txnEntry) lockSession() string {
	lease, _, err := e.suite.client.Session().CreateNoChecks(e.suite.store1.createConsulLockSession(e.id), nil)
	e.suite.Require().NoError(err)
	e.suite.T().Cleanup(func() { _, _ = e.suite.client.Session().Destroy(lease, nil) })
	return lease
}

func (e txnEntry) get() *api.KVPair {
	pair, _, err := e.suite.client.KV().Get(e.key, nil)
	e.suite.Require().NoError(err)
	e.suite.Require().NotNil(pair)
	return pair
}

// A takeover is one transaction, conditional on the index its decision was
// read at. Against an entry that has changed since, it fails as a whole: the
// old holder's unlock doesn't apply without the new holder's lock, and the
// entry keeps its value and its holder.
func (suite *ConsulStoreTestSuite) TestATakeoverAgainstAStaleIndexChangesNothing() {
	kv, e := suite.client.KV(), suite.txnEntry("stale-takeover")
	old, next := e.lockSession(), e.lockSession()
	ok, _, err := kv.Acquire(&api.KVPair{Key: e.key, Value: e.value(1), Session: old}, nil)
	suite.Require().NoError(err)
	suite.Require().True(ok)
	stale := e.get()
	// The entry moves on, under the same holder.
	ok, _, err = kv.Acquire(&api.KVPair{Key: e.key, Value: e.value(2), Session: old}, nil)
	suite.Require().NoError(err)
	suite.Require().True(ok)
	before := e.get()
	suite.Require().Greater(before.ModifyIndex, stale.ModifyIndex)

	ok, resp, _, err := kv.Txn(api.KVTxnOps{
		{Verb: api.KVCheckIndex, Key: e.key, Index: stale.ModifyIndex},
		{Verb: api.KVUnlock, Key: e.key, Value: e.value(3), Session: old},
		{Verb: api.KVLock, Key: e.key, Value: e.value(3), Session: next},
	}, nil)
	suite.Require().NoError(err)
	suite.False(ok, "a takeover against a stale index committed")
	suite.NotEmpty(resp.Errors)
	after := e.get()
	suite.Equal(before.Value, after.Value)
	suite.Equal(old, after.Session, "the entry changed holder")
	suite.Equal(before.ModifyIndex, after.ModifyIndex)
}

// A registration of an absent ID creates the entry only if it's still absent.
// Against an entry that exists, it fails and leaves the entry as it was.
func (suite *ConsulStoreTestSuite) TestACreateAgainstAnExistingEntryChangesNothing() {
	kv, e := suite.client.KV(), suite.txnEntry("create-existing")
	holder, next := e.lockSession(), e.lockSession()
	ok, _, err := kv.Acquire(&api.KVPair{Key: e.key, Value: e.value(1), Session: holder}, nil)
	suite.Require().NoError(err)
	suite.Require().True(ok)
	before := e.get()

	ok, resp, _, err := kv.Txn(api.KVTxnOps{
		{Verb: api.KVCheckNotExists, Key: e.key},
		{Verb: api.KVLock, Key: e.key, Value: e.value(2), Session: next},
	}, nil)
	suite.Require().NoError(err)
	suite.False(ok, "a create against an existing entry committed")
	suite.NotEmpty(resp.Errors)
	after := e.get()
	suite.Equal(before.Value, after.Value)
	suite.Equal(holder, after.Session, "the entry changed holder")
	suite.Equal(before.ModifyIndex, after.ModifyIndex)
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

// A plain write over a held key keeps its lock: the premise is asserted, not
// assumed, so a Consul version that behaves otherwise fails here rather than
// silently making the case unreachable.
func (suite *ConsulStoreTestSuite) TestReregisterRestoresAnUnreadableValueItsLeaseHolds() {
	ctx, id := context.Background(), suite.uniq("unreadable")
	reg, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22"}) // legacy
	suite.Require().NoError(err)
	_, err = suite.client.KV().Put(&api.KVPair{Key: suite.store1.SessionKey(id), Value: []byte("not json")}, nil)
	suite.Require().NoError(err)
	pair, _, err := suite.client.KV().Get(suite.store1.SessionKey(id), nil)
	suite.Require().NoError(err)
	suite.Require().Equal(reg.lease, pair.Session, "a plain write kept the lock")

	next, err := suite.store1.Reregister(ctx, reg)
	suite.Require().NoError(err, "the registration's own lease holds the key")
	defer func() { _ = suite.store1.Release(ctx, next) }()
	pair, s := suite.consulGet(id)
	suite.Require().NotNil(s)
	suite.Equal("a:22", s.NodeAddr)
	suite.Equal(next.lease, pair.Session, "the rebuild moved the lock to its new lease")

	// Unreadable, and held by no lock: still refused for a legacy rebuild.
	other := suite.uniq("unreadable-unlocked")
	reg2, err := suite.store1.Register(ctx, &Session{ID: other, NodeAddr: "a:22"})
	suite.Require().NoError(err)
	_, err = suite.client.Session().Destroy(reg2.lease, nil)
	suite.Require().NoError(err)
	_, err = suite.client.KV().Put(&api.KVPair{Key: suite.store1.SessionKey(other), Value: []byte("not json")}, nil)
	suite.Require().NoError(err)
	_, err = suite.store1.Reregister(ctx, reg2)
	suite.ErrorIs(err, ErrSuperseded)
}

// The lease that holds a key makes its value the registration's own, whatever
// was written into it: a value that parses as something that is no registration
// is restored too. Such a value reaches the watch as a session with no ID, so
// the registration's own ID goes missing from the replica and the keeper
// rebuilds.
func (suite *ConsulStoreTestSuite) TestReregisterRestoresAValueNoRegistrationItsLeaseHolds() {
	ctx := context.Background()
	for _, value := range []string{`{}`, `null`, `{"unrelated":true}`} {
		id := suite.uniq("no-registration")
		reg, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22"}) // legacy
		suite.Require().NoError(err)
		_, err = suite.client.KV().Put(&api.KVPair{Key: suite.store1.SessionKey(id), Value: []byte(value)}, nil)
		suite.Require().NoError(err)
		var parsed Session
		suite.Require().NoError(json.Unmarshal([]byte(value), &parsed), "%s parses, as no registration", value)
		pair, _, err := suite.client.KV().Get(suite.store1.SessionKey(id), nil)
		suite.Require().NoError(err)
		suite.Require().Equal(reg.lease, pair.Session, "a plain write of %s kept the lock", value)

		next, err := suite.store1.Reregister(ctx, reg)
		suite.Require().NoError(err, "the registration's own lease holds %s", value)
		pair, s := suite.consulGet(id)
		suite.Require().NotNil(s)
		suite.Equal(id, s.ID)
		suite.Equal("a:22", s.NodeAddr)
		suite.Equal(next.lease, pair.Session, "the rebuild moved the lock to its new lease")
		suite.NoError(suite.store1.Release(ctx, next))
	}
}

// A rebuild from a handle whose lease no longer holds the key is refused,
// however unreadable the value: the key is another registration's entry, and
// a foreign write into it doesn't make it the stale handle's.
func (suite *ConsulStoreTestSuite) TestReregisterRefusesAValueAnotherLeaseHolds() {
	ctx := context.Background()
	for _, value := range []string{"not json", `{}`} {
		id := suite.uniq("another-lease")
		stale, err := suite.store1.Register(ctx, &Session{ID: id, NodeAddr: "a:22"}) // legacy
		suite.Require().NoError(err)
		next, err := suite.store1.Reregister(ctx, stale)
		suite.Require().NoError(err)
		_, err = suite.client.KV().Put(&api.KVPair{Key: suite.store1.SessionKey(id), Value: []byte(value)}, nil)
		suite.Require().NoError(err)
		before, _, err := suite.client.KV().Get(suite.store1.SessionKey(id), nil)
		suite.Require().NoError(err)
		suite.Require().Equal(next.lease, before.Session, "a plain write of %s kept the successor's lock", value)
		suite.Require().NotEqual(stale.lease, before.Session)

		_, err = suite.store1.Reregister(ctx, stale)
		suite.ErrorIs(err, ErrSuperseded, "%s held by another lease", value)
		after, _, err := suite.client.KV().Get(suite.store1.SessionKey(id), nil)
		suite.Require().NoError(err)
		suite.Equal(before.ModifyIndex, after.ModifyIndex, "a refused rebuild writes nothing")
		suite.Equal(next.lease, after.Session)

		// The holder's own rebuild restores it.
		restored, err := suite.store1.Reregister(ctx, next)
		suite.Require().NoError(err)
		suite.NoError(suite.store1.Release(ctx, restored))
	}
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
	consulURL := suite.consulURL
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
	consulURL := suite.consulURL
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
// replies to the ones whose ordinals it was made with, each until its own
// release. Ordinals count from 1 the transactions that went through it and
// were answered; one that fails to reach Consul isn't counted.
type delayedTxnReply struct {
	next  http.RoundTripper
	txns  atomic.Int64
	holds map[int]*heldReply // fixed at construction
}

// heldReply is one held transaction's acknowledgement and release.
type heldReply struct {
	entered chan struct{}
	resume  chan struct{}
	resumed sync.Once
}

// newDelayedTxnReply holds the replies to the transactions numbered hold,
// counted as delayedTxnReply says; the others pass through, so a later
// transaction never waits on an earlier one that is held.
func newDelayedTxnReply(next http.RoundTripper, hold ...int) *delayedTxnReply {
	d := &delayedTxnReply{next: next, holds: make(map[int]*heldReply, len(hold))}
	for _, n := range hold {
		d.holds[n] = &heldReply{entered: make(chan struct{}), resume: make(chan struct{})}
	}
	return d
}

func (d *delayedTxnReply) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := d.next.RoundTrip(r)
	if err == nil && r.URL.Path == "/v1/txn" {
		if h, ok := d.holds[int(d.txns.Add(1))]; ok {
			close(h.entered)
			<-h.resume
		}
	}
	return resp, err
}

// entered closes once the nth transaction's reply is held: Consul has applied
// it, and its caller hasn't had the reply.
func (d *delayedTxnReply) entered(n int) <-chan struct{} { return d.held(n).entered }

// release lets the nth transaction's reply through. It is idempotent.
func (d *delayedTxnReply) release(n int) {
	h := d.held(n)
	h.resumed.Do(func() { close(h.resume) })
}

func (d *delayedTxnReply) held(n int) *heldReply {
	h, ok := d.holds[n]
	if !ok {
		panic(fmt.Sprintf("delayedTxnReply doesn't hold transaction %d", n))
	}
	return h
}

// storeWithADelayedReply is a store of its own, on the suite's key prefix,
// whose first transaction's reply arrives only once the returned delay is
// released. Its watch runs on a client of its own, and isn't delayed.
func (suite *ConsulStoreTestSuite) storeWithADelayedReply() (*consulSessionStore, *delayedTxnReply) {
	consulURL := suite.consulURL
	store, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
	suite.Require().NoError(err)
	delay := newDelayedTxnReply(http.DefaultTransport, 1)
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
	case <-delay.entered(1):
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
	defer delay.release(1)
	ctx, id := context.Background(), suite.uniq("late-reply")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	reg2, err := store.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = store.Release(ctx, reg2) }()
	delay.release(1)
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
	defer delay.release(1)
	ctx, id := context.Background(), suite.uniq("late-reply-other-node")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	reg2, err := suite.store2.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	defer func() { _ = suite.store2.Release(ctx, reg2) }()
	suite.Require().Eventually(func() bool { return cachedGeneration(store, id) == 2 },
		2*time.Second, 10*time.Millisecond, "the watch never delivered generation 2")
	delay.release(1)
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
	defer delay.release(1)
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
	delay.release(1)
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
//
// It can hold that reply before losing it. entered, if not nil, closes once
// Consul has applied the transaction; resume, if not nil, holds the loss until
// it closes, and the test closes it once. Nil channels lose the reply at once.
type lostTxnReply struct {
	lost    atomic.Bool
	next    http.RoundTripper
	entered chan struct{}
	resume  chan struct{}
}

func (l *lostTxnReply) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := l.next.RoundTrip(r)
	if err == nil && r.URL.Path == "/v1/txn" && l.lost.CompareAndSwap(false, true) {
		if l.entered != nil {
			close(l.entered)
		}
		if l.resume != nil {
			<-l.resume
		}
		_ = resp.Body.Close()
		return nil, errors.New("reply lost")
	}
	return resp, err
}

// A registration whose transaction committed but whose reply was lost finds
// its own entry when it retries. That is its own write, not a registration to
// order it against: it succeeds, and the entry stays under its lease.
func (suite *ConsulStoreTestSuite) TestALostReplyToACommittedRegistrationStillSucceeds() {
	consulURL := suite.consulURL
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
	defer delay.release(1)
	ctx, id := context.Background(), suite.uniq("late-reply-removed")

	first := suite.registerDelayed(store, delay, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	reg2, err := suite.store2.Register(ctx, &Session{ID: id, NodeAddr: "b:22", Generation: 2})
	suite.Require().NoError(err)
	suite.Require().Eventually(func() bool { return cachedGeneration(store, id) == 2 },
		2*time.Second, 10*time.Millisecond, "the watch never delivered generation 2")
	suite.Require().NoError(suite.store2.Release(ctx, reg2))
	suite.Require().Eventually(func() bool { return !store.HasInCache(id) },
		2*time.Second, 10*time.Millisecond, "the watch never delivered the removal")
	delay.release(1)
	reg1 := suite.awaitRegistered(first)
	defer func() { _ = store.Release(ctx, reg1) }()

	suite.False(store.HasInCache(id), "the late reply cached a registration that was superseded and removed")
	_, err = store.Get(id)
	suite.Error(err, "a removed registration is still found")
}

// A guest whose cached route failed reads its session again with GetFresh. If
// the entry is gone from Consul by then, the cached one goes too: on a quiet
// relay the next watch delivery could be a long way off, and until then later
// guests would be routed to a host that has left, and not told it has.
func (suite *ConsulStoreTestSuite) TestAFreshReadThatFindsTheEntryGoneUncachesIt() {
	consulURL := suite.consulURL
	store, err := newConsulSessionStore(consulURL, 5*time.Minute, sessionTestLogger)
	suite.Require().NoError(err)
	defer func() { _ = store.Close() }()
	ctx, id := context.Background(), suite.uniq("fresh-read-gone")

	reg, err := store.Register(ctx, &Session{ID: id, NodeAddr: "a:22", Generation: 1})
	suite.Require().NoError(err)
	defer func() { _ = store.Release(ctx, reg) }()
	// Stop the watch, so only the fresh read can learn of the removal.
	store.watchPlan.Stop()
	suite.Require().True(store.HasInCache(id))
	_, err = suite.client.KV().Delete(store.SessionKey(id), nil)
	suite.Require().NoError(err)

	_, err = store.GetFresh(ctx, id)
	var missing *ErrSessionNotFound
	suite.Require().ErrorAs(err, &missing)
	suite.False(store.HasInCache(id), "the entry the fresh read found gone is still cached")
}

// Without renewal, Consul expires an entry within twice its TTL, which is at
// least 10 s.
func (suite *ConsulStoreTestSuite) TestLeaseExpiryAndRenewal() {
	consulURL := suite.consulURL
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

// fakeConsul answers the calls a store makes for a single session entry. It
// applies every transaction whatever its checks. It answers no renewals (an
// unexpected request fails the test), so a test on it ends before a lease
// keeper's first renewal, at half the store's TTL.
//
// Its transactions' writes take their indexes from nextIndex. By default the
// first is at index 100 and every later one at 6, as when Consul's index goes
// backwards between them; a delete takes no index, and writeOver writes just
// past the registration it writes over. In monotonic mode every change to the
// entry, writeOver's and a delete included, takes the next index of one rising
// sequence. reset loses the entry, as a restore can.
//
// It tracks the lock sessions it creates (live), records every one it destroys
// (destroyed), and wakes a waiter (changed) after each change to them or to the
// entry.
type fakeConsul struct {
	*httptest.Server
	mu   sync.Mutex
	pair *api.KVPair
	// monotonic has every change to the entry take the next of 100, 101,
	// 102, …; the monotonicIndexes option sets it.
	monotonic bool
	leases    int
	writes    int    // indexes nextIndex has given out
	last      uint64 // the last of them
	alive     map[string]bool
	destroys  []string
	changes   chan struct{}
}

// monotonicIndexes is a newFakeConsul option: every change to the entry, a
// delete included, takes the next index of one rising sequence from 100, so a
// delivery of what snapshot read is never older than anything the fake had
// done by then.
func monotonicIndexes(f *fakeConsul) { f.monotonic = true }

func newFakeConsul(t *testing.T, options ...func(*fakeConsul)) *fakeConsul {
	f := &fakeConsul{alive: make(map[string]bool), changes: make(chan struct{}, 1)}
	for _, option := range options {
		option(f)
	}
	// Each change is signalled before its reply is written, so a waiter that
	// sees a call return finds its wakeup already queued.
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/session/create":
			f.leases++
			lease := fmt.Sprintf("lease-%d", f.leases)
			f.alive[lease] = true
			f.pokeLocked()
			_ = json.NewEncoder(w).Encode(map[string]string{"ID": lease})
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
				f.deleteLocked()
				f.pokeLocked()
				_ = json.NewEncoder(w).Encode(api.TxnResponse{})
				return
			}
			f.pair = &api.KVPair{Key: last.Key, Value: last.Value, Session: last.Session, ModifyIndex: f.nextIndex()}
			f.pokeLocked()
			_ = json.NewEncoder(w).Encode(api.TxnResponse{Results: api.TxnResults{&api.TxnResult{KV: f.pair}}})
		case strings.HasPrefix(r.URL.Path, "/v1/session/destroy/"):
			lease := strings.TrimPrefix(r.URL.Path, "/v1/session/destroy/")
			f.destroys = append(f.destroys, lease)
			delete(f.alive, lease)
			if f.pair != nil && f.pair.Session == lease {
				f.deleteLocked()
			}
			f.pokeLocked()
			_, _ = w.Write([]byte("true"))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// nextIndex is the fake's one index allocator: its transactions' writes take
// their indexes from it, and in monotonic mode so do writeOver and every
// delete. The caller holds f.mu. By default it gives 100, then 6 ever after;
// in monotonic mode it counts up from 100.
func (f *fakeConsul) nextIndex() uint64 {
	f.writes++
	switch {
	case f.monotonic:
		f.last = 99 + uint64(f.writes)
	case f.writes == 1:
		f.last = 100
	default:
		f.last = 6
	}
	return f.last
}

// index is the last index nextIndex gave out, 0 before any: in monotonic mode,
// that of the fake's latest change. A delivery of the fake's current state
// takes its index and entry from snapshot, which reads both under one lock:
// read apart, a change can land between them, and the delivery pair one
// change's entry with another's index.
func (f *fakeConsul) index() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last
}

// snapshot is what a watch delivery of the fake's current state carries: its
// entry, if it has one, and index(), read under one lock, so no change lands
// between the two.
func (f *fakeConsul) snapshot() (uint64, api.KVPairs) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pair == nil {
		return f.last, nil
	}
	return f.last, api.KVPairs{f.pair}
}

// deleteLocked removes the entry. In monotonic mode the delete moves the index
// on, as Consul's does; by default it takes none. The caller holds f.mu.
func (f *fakeConsul) deleteLocked() {
	f.pair = nil
	if f.monotonic {
		f.nextIndex()
	}
}

// pokeLocked wakes changed's waiter, if it isn't already due a wakeup. The
// caller holds f.mu, so the waiter's re-read finds the change.
func (f *fakeConsul) pokeLocked() {
	select {
	case f.changes <- struct{}{}:
	default:
	}
}

// changed receives after the entry is written or deleted, or a lock session
// is created or destroyed. It holds one wakeup, which stands for every change
// since the last receive, so a waiter re-reads what it waits for each time.
func (f *fakeConsul) changed() <-chan struct{} { return f.changes }

// live reports whether lease was created here and hasn't been destroyed.
func (f *fakeConsul) live(lease string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive[lease]
}

// destroyed is every lock session destroyed here, in order, whether or not it
// held the entry.
func (f *fakeConsul) destroyed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.destroys)
}

func (f *fakeConsul) entry() *api.KVPair {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pair
}

// reset loses the entry, a delete as deleteLocked indexes it, and leaves the
// lock sessions as they are.
func (f *fakeConsul) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteLocked()
	f.pokeLocked()
}

// newFakeConsulStore is a store on f with no watch running; tests deliver
// what the watch would.
func newFakeConsulStore(t *testing.T, f *fakeConsul) *consulSessionStore {
	return newFakeConsulStoreWith(t, f, nil)
}

// newFakeConsulStoreWith is newFakeConsulStore with its calls to f made
// through rt, such as a delayedTxnReply or a lostTxnReply; nil keeps the
// client's own transport. The store's calls are its only traffic: with no
// watch running, rt holds nothing a delivery needs.
func newFakeConsulStoreWith(t *testing.T, f *fakeConsul, rt http.RoundTripper) *consulSessionStore {
	cfg := api.DefaultConfig()
	cfg.Address = f.URL
	if rt != nil {
		cfg.HttpClient = &http.Client{Transport: rt}
	}
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	logger := slog.New(slog.DiscardHandler)
	return &consulSessionStore{client: client, logger: logger, ttl: time.Minute, keyPrefix: "fake",
		cache: newSessionCache(logger), held: make(map[string]map[string]struct{})}
}

// The fake records every lease destroyed, whether or not it held the entry,
// and only the lease that holds the entry takes it along. Each destroy is a
// change a waiter is woken for.
func TestFakeConsulRecordsEveryLeaseItDestroys(t *testing.T) {
	consul := newFakeConsul(t)
	store := newFakeConsulStore(t, consul)
	ctx := context.Background()
	first, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1})
	require.NoError(t, err)
	second, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-b:22", Generation: 2})
	require.NoError(t, err)
	require.NotEqual(t, first.lease, second.lease)
	require.Equal(t, second.lease, consul.entry().Session, "the entry isn't under the second lease")
	require.True(t, consul.live(first.lease))
	require.True(t, consul.live(second.lease))
	poked := func() bool {
		select {
		case <-consul.changed():
			return true
		default:
			return false
		}
	}
	poked() // the registrations' own changes

	require.NoError(t, store.Release(ctx, first))
	assert.True(t, poked(), "destroying a lease that doesn't hold the entry was no change")
	require.NotNil(t, consul.entry(), "destroying a lease that doesn't hold the entry removed it")
	assert.Equal(t, second.lease, consul.entry().Session)
	assert.Equal(t, []string{first.lease}, consul.destroyed())
	assert.False(t, consul.live(first.lease))
	assert.True(t, consul.live(second.lease))

	require.NoError(t, store.Release(ctx, second))
	assert.True(t, poked(), "destroying the lease that holds the entry was no change")
	assert.Nil(t, consul.entry(), "destroying the lease that holds the entry left it")
	assert.Equal(t, []string{first.lease, second.lease}, consul.destroyed())
	assert.False(t, consul.live(first.lease))
	assert.False(t, consul.live(second.lease))
}

// In monotonic mode every change to the entry takes the next index of one
// sequence: a registration's write, a plain write over it, the next
// registration's write, and a delete.
func TestFakeConsulIndexesOneSequence(t *testing.T) {
	consul := newFakeConsul(t, monotonicIndexes)
	store := newFakeConsulStore(t, consul)
	ctx := context.Background()
	first, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1})
	require.NoError(t, err)
	// No registration to write over: the write follows the entry's lease.
	over := writeOver(t, consul, nil, &Session{ID: "id", NodeAddr: "node-b:22", Generation: 1})
	assert.Equal(t, first.lease, over.Session, "a plain write moved the lock")
	second, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 2})
	require.NoError(t, err)
	assert.Equal(t, []uint64{100, 101, 102}, []uint64{first.index, over.ModifyIndex, second.index})
	assert.Equal(t, uint64(102), consul.index())

	require.NoError(t, store.Release(ctx, second)) // the entry goes with the lease that holds it
	require.Nil(t, consul.entry())
	assert.Equal(t, uint64(103), consul.index(), "a delete didn't move the index")
}

// By default the fake's index goes backwards after its first write, as
// Consul's can, and a plain write lands just past the registration it writes
// over, outside that sequence.
func TestFakeConsulDefaultModeKeepsItsIndexes(t *testing.T) {
	consul := newFakeConsul(t)
	store := newFakeConsulStore(t, consul)
	ctx := context.Background()
	first, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 1})
	require.NoError(t, err)
	assert.Equal(t, uint64(100), first.index)
	over := writeOver(t, consul, first, &Session{ID: "id", NodeAddr: "node-b:22", Generation: 1})
	assert.Equal(t, uint64(101), over.ModifyIndex)
	second, err := store.Register(ctx, &Session{ID: "id", NodeAddr: "node-a:22", Generation: 2})
	require.NoError(t, err)
	assert.Equal(t, uint64(6), second.index)
	assert.Equal(t, uint64(6), consul.index())
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

// A value that parses but names no session, such as `{}` or `null` written
// into a key by hand, is no registration. The watch leaves it out of the cache
// and out of the view it hands the observers, rather than keying it under the
// empty ID.
func TestTheWatchLeavesOutAValueThatNamesNoSession(t *testing.T) {
	store := newFakeConsulStore(t, newFakeConsul(t))
	var seen map[string]StoreEntry
	store.Observe(func(_, _ uint64, entries map[string]StoreEntry) { seen = entries })
	stored, err := json.Marshal(&Session{ID: "id", NodeAddr: "node", Generation: 1})
	require.NoError(t, err)

	store.updateSessionReplica(10, api.KVPairs{
		{Key: store.SessionKey("a"), Value: []byte("{}"), ModifyIndex: 8},
		{Key: store.SessionKey("b"), Value: []byte("null"), ModifyIndex: 9},
		{Key: store.SessionKey("id"), Value: stored, ModifyIndex: 10},
	})

	assert.False(t, store.HasInCache(""), "a value that names no session was cached under the empty ID")
	assert.NotContains(t, seen, "", "the observers were handed a value that names no session")
	assert.True(t, store.HasInCache("id"))
	assert.Contains(t, seen, "id")
}

// A guest whose cached route failed reads its session again with GetFresh,
// which goes to Consul even though the cache holds an entry: the watch may not
// have caught up with the host's move yet. What it reads then replaces the
// stale entry, under the cache's usual rules.
func TestConsulGetFreshReadsPastTheCache(t *testing.T) {
	consul := newFakeConsul(t)
	store := newFakeConsulStore(t, consul)
	store.cache.Set("id", cachedSession{session: &Session{ID: "id", NodeAddr: "a:22", Generation: 1}, index: 100}, store.cache.Epoch())
	moved, err := json.Marshal(&Session{ID: "id", NodeAddr: "c:22", Generation: 2})
	require.NoError(t, err)
	consul.mu.Lock()
	consul.pair = &api.KVPair{Key: store.SessionKey("id"), Value: moved, Session: "lease", ModifyIndex: 200}
	consul.mu.Unlock()

	cached, err := store.Get("id")
	require.NoError(t, err)
	require.Equal(t, "a:22", cached.NodeAddr)
	fresh, err := store.GetFresh(context.Background(), "id")
	require.NoError(t, err)
	require.Equal(t, "c:22", fresh.NodeAddr)
	require.Equal(t, uint64(2), fresh.Generation)
	cached, err = store.Get("id")
	require.NoError(t, err)
	require.Equal(t, "c:22", cached.NodeAddr, "the fresh read didn't update the cache")
}

// stalledTransport holds every request until its context is done.
type stalledTransport struct{}

func (stalledTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}

// GetFresh runs inside a guest's upstream stage, so a Consul that doesn't
// answer must not hold it past ctx, whatever attempts it has left.
func TestConsulGetFreshHonoursItsContext(t *testing.T) {
	store := newFakeConsulStore(t, newFakeConsul(t))
	cfg := api.DefaultConfig()
	cfg.HttpClient = &http.Client{Transport: stalledTransport{}}
	client, err := api.NewClient(cfg)
	require.NoError(t, err)
	store.client = client
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := store.GetFresh(ctx, "id")
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("GetFresh outlived its context")
	}
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

// A read that finds an entry gone evicts the cached one only if it saw that
// entry's write: within the read's epoch, and at or past the write's index.
func TestSessionCacheEvictsOnlyWhatTheReadSawGone(t *testing.T) {
	c := newSessionCache(sessionTestLogger)
	entry := func(index uint64) cachedSession {
		return cachedSession{session: &Session{ID: "id", Generation: 1}, index: index}
	}

	c.Set("id", entry(20), c.Epoch())
	c.Evict("id", 15, c.Epoch())
	assert.True(t, c.Has("id"), "a read from before the write evicted it")
	c.Evict("id", 20, c.Epoch())
	assert.False(t, c.Has("id"), "a read that saw the write left it")

	c.ReplaceAll(30, map[string]cachedSession{"id": entry(30)})
	before := c.Epoch()                                       // a read begins
	c.ReplaceAll(5, map[string]cachedSession{"id": entry(4)}) // the index drops
	c.Evict("id", 40, before)                                 // and the read finds the entry gone
	assert.True(t, c.Has("id"), "a read from before an index drop evicted an entry from after it")
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
