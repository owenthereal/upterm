package server

import (
	"fmt"
	"sync"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

type session struct {
	ID                   string
	HostUser             string
	NodeAddr             string
	HostPublicKeys       []ssh.PublicKey
	ClientAuthorizedKeys []ssh.PublicKey
}

func (s session) IsClientKeyAllowed(key ssh.PublicKey) bool {
	if len(s.ClientAuthorizedKeys) == 0 {
		return true
	}

	for _, k := range s.ClientAuthorizedKeys {
		if gssh.KeysEqual(k, key) {
			return true
		}
	}

	return false
}

func newSession(id, hostUser, NodeAddr string, hostPublicKeys, clientAuthorizedKeys [][]byte) (*session, error) {
	var (
		hpk []ssh.PublicKey
		cak []ssh.PublicKey
	)

	for _, k := range hostPublicKeys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey(k)
		if err != nil {
			return nil, err
		}
		hpk = append(hpk, pk)
	}

	for _, k := range clientAuthorizedKeys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey(k)
		if err != nil {
			return nil, err
		}
		cak = append(cak, pk)
	}

	return &session{
		ID:                   id,
		HostUser:             hostUser,
		NodeAddr:             NodeAddr,
		HostPublicKeys:       hpk,
		ClientAuthorizedKeys: cak,
	}, nil
}

func newSessionRepo() *sessionRepo {
	return &sessionRepo{
		sessions: make(map[string]session),
	}
}

type sessionRepo struct {
	sessions map[string]session
	mutex    sync.Mutex
}

func (s *sessionRepo) Add(sess session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, ok := s.sessions[sess.ID]
	if ok {
		return fmt.Errorf("session already exists")
	}

	s.sessions[sess.ID] = sess
	return nil
}

func (s *sessionRepo) Get(id string) (*session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("no session is found")
	}

	return &sess, nil
}

func (s *sessionRepo) Delete(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.sessions, id)
}
