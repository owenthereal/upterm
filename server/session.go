package server

import (
	"fmt"
	"sync"
)

type Session struct {
	ID                   string
	HostUser             string
	HostPublicKeys       [][]byte
	ClientAuthorizedKeys [][]byte
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

func (s *SessionRepo) Store(sess Session) error {
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
