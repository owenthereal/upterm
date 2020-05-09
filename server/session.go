package server

import (
	"fmt"
	"sync"

	gssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

type Session struct {
	ID                   string
	HostUser             string
	HostPublicKeys       []ssh.PublicKey
	ClientAuthorizedKeys []ssh.PublicKey
}

func (s Session) IsClientKeyAllowed(key ssh.PublicKey) bool {
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

func newSession(id, hostUser string, hostPublicKeys, clientAuthorizedKeys [][]byte) (*Session, error) {
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

	return &Session{
		ID:                   id,
		HostUser:             hostUser,
		HostPublicKeys:       hpk,
		ClientAuthorizedKeys: cak,
	}, nil
}

func newSessionRepo() *SessionRepo {
	return &SessionRepo{
		sessions: make(map[string]Session),
	}
}

type SessionRepo struct {
	sessions map[string]Session
	mutex    sync.Mutex
}

func (s *SessionRepo) Add(sess Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, ok := s.sessions[sess.ID]
	if ok {
		return fmt.Errorf("session already exists")
	}

	s.sessions[sess.ID] = sess
	return nil
}

func (s *SessionRepo) Get(id string) (*Session, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("no session is found")
	}

	return &sess, nil
}

func (s *SessionRepo) Delete(id string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.sessions, id)
}
