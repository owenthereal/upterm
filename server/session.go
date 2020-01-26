package server

import (
	"fmt"
	"sync"
)

func newInMemorySessionService(nodeAddr string) SessionService {
	return &inMemorySessionService{nodeAddr: nodeAddr}
}

type Session struct {
	ID       string
	NodeAddr string
}

type SessionService interface {
	CreateSession(id string) error
	GetSession(id string) (*Session, error)
	DeleteSession(id string) error
}

type inMemorySessionService struct {
	nodeAddr string
	sessions sync.Map
}

func (s *inMemorySessionService) CreateSession(id string) error {
	actual, loaded := s.sessions.LoadOrStore(id, &Session{ID: id, NodeAddr: s.nodeAddr})
	if loaded {
		return fmt.Errorf("session %s already exist: %v", id, actual)
	}

	return nil
}

func (s *inMemorySessionService) GetSession(id string) (*Session, error) {
	val, exist := s.sessions.Load(id)
	if !exist {
		return nil, fmt.Errorf("session %s not found", id)
	}

	return val.(*Session), nil
}

func (s *inMemorySessionService) DeleteSession(id string) error {
	s.sessions.Delete(id)
	return nil
}
