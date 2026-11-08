package server

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/owenthereal/upterm/routing"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// localRouteRecord is the route record a local registration of generation 1
// writes: the authority hint first, then the fields that predate it. Each
// host key is its authorized_keys line, newline included, in base64.
const localRouteRecord = `{"mode":"local","ID":"abcdefghijklmnopqrst","NodeAddr":"127.0.0.1:2222","Generation":1,"HostUser":"alice","HostPublicKeys":["c3NoLWVkMjU1MTkgQUFBQUMzTnphQzFsWkRJMU5URTVBQUFBSUFBQkFnTUVCUVlIQ0FrS0N3d05EZzhRRVJJVEZCVVdGeGdaR2hzY0hSNGYK"],"ClientAuthorizedKeys":null}`

// layoutHostKey is the ed25519 key whose 32 bytes are 0x00 to 0x1f.
func layoutHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	raw := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range raw {
		raw[i] = byte(i)
	}
	key, err := ssh.NewPublicKey(raw)
	require.NoError(t, err)
	return key
}

func layoutSession(t *testing.T) *Session {
	t.Helper()
	return &Session{AuthorityHint: AuthorityLocal, ID: "abcdefghijklmnopqrst", NodeAddr: "127.0.0.1:2222",
		Generation: 1, HostUser: "alice", HostPublicKeys: []ssh.PublicKey{layoutHostKey(t)}}
}

// The route record's bytes and key are a contract between nodes of different
// versions: every node writes these, and reads what any other writes.
func TestRouteRecordLayoutGolden(t *testing.T) {
	session := layoutSession(t)
	encoded, err := session.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, localRouteRecord, string(encoded))

	fake := newFakeConsul(t, monotonicIndexes)
	store := newFakeConsulStore(t, fake)
	store.keyPrefix = DefaultKeyPrefix
	reg, err := store.Register(t.Context(), session)
	require.NoError(t, err)
	pair := fake.entry()
	require.NotNil(t, pair)
	require.Equal(t, "uptermd/sessions/abcdefghijklmnopqrst", pair.Key)
	require.Equal(t, localRouteRecord, string(pair.Value))
	require.NoError(t, store.Release(t.Context(), reg))

	// A host's registration writes the same layout, its hint included.
	written := newFakeConsul(t, monotonicIndexes)
	writtenStore := newFakeConsulStore(t, written)
	writtenStore.keyPrefix = DefaultKeyPrefix
	srv := newTestSSHD(t, func(s *sshd) {
		s.SessionManager = newSessionManagerWithStore(writtenStore, routing.NewEncodeDecoder(routing.ModeConsul))
	})
	p := newProven(t)
	ok, body := p.register(t, srv.dialAs(t, "conn-1"), "conn-1", 1)
	require.True(t, ok, "%q", body)
	pair = written.entry()
	require.NotNil(t, pair)
	require.Equal(t, "uptermd/sessions/"+p.id(), pair.Key)
	want, err := (&Session{AuthorityHint: AuthorityLocal, ID: p.id(), NodeAddr: srv.sshd.NodeAddr, Generation: 1,
		HostUser: "owen", HostPublicKeys: []ssh.PublicKey{p.key.PublicKey()}}).MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, string(want), string(pair.Value))
	require.True(t, strings.HasPrefix(string(pair.Value), `{"mode":"local","ID":`), "%s", pair.Value)

	var decoded Session
	require.NoError(t, json.Unmarshal([]byte(localRouteRecord), &decoded))
	require.Equal(t, *session, decoded)

	unhinted := decoded
	unhinted.AuthorityHint = ""
	for name, record := range map[string]string{
		"without the hint": strings.Replace(localRouteRecord, `"mode":"local",`, "", 1),
		`"oss"`:            strings.Replace(localRouteRecord, `"mode":"local"`, `"mode":"oss"`, 1),
		`"managed"`:        strings.Replace(localRouteRecord, `"mode":"local"`, `"mode":"managed"`, 1),
		"7":                strings.Replace(localRouteRecord, `"mode":"local"`, `"mode":7`, 1),
	} {
		require.NotEqual(t, localRouteRecord, record, name)
		var got Session
		require.NoError(t, json.Unmarshal([]byte(record), &got), name)
		require.Equal(t, unhinted, got, name)
	}
}

// A node from before the hint reads a record that carries it, and finds
// everything it knows of.
func TestOldNodesReadNewRecords(t *testing.T) {
	// The struct a v0.40.0 node decodes a route record into, copied from it.
	type sessionJSON struct {
		ID                   string
		NodeAddr             string
		Generation           uint64 `json:",omitempty"`
		HostUser             string
		HostPublicKeys       [][]byte
		ClientAuthorizedKeys [][]byte
	}
	var old sessionJSON
	require.NoError(t, json.Unmarshal([]byte(localRouteRecord), &old))
	require.Equal(t, sessionJSON{ID: "abcdefghijklmnopqrst", NodeAddr: "127.0.0.1:2222", Generation: 1, HostUser: "alice",
		HostPublicKeys: [][]byte{ssh.MarshalAuthorizedKey(layoutHostKey(t))}}, old)
	for _, line := range old.HostPublicKeys {
		_, _, _, _, err := ssh.ParseAuthorizedKey(line)
		require.NoError(t, err)
	}
}
