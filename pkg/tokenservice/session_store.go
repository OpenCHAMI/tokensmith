// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"sync"
	"time"
)

// SessionToken represents a stored session token for revocation tracking
type SessionToken struct {
	SessionID string
	TokenID   string
	Subject   string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
	RevokedAt *time.Time
}

// SessionStore provides in-memory storage for session tokens
type SessionStore struct {
	mu        sync.RWMutex
	sessions  map[string]*SessionToken
	byTokenID map[string]*SessionToken
}

// NewSessionStore creates a new session storage instance
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions:  make(map[string]*SessionToken),
		byTokenID: make(map[string]*SessionToken),
	}
}

// SaveSession stores a session token for revocation tracking
func (s *SessionStore) SaveSession(session *SessionToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.SessionID] = session
	s.byTokenID[session.TokenID] = session

	return nil
}

// GetSessionByID retrieves a session by session_id
func (s *SessionStore) GetSessionByID(sessionID string) (*SessionToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	return session, ok
}

// GetSessionByTokenID retrieves a session by token_id (jti)
func (s *SessionStore) GetSessionByTokenID(tokenID string) (*SessionToken, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.byTokenID[tokenID]
	return session, ok
}

// RevokeSession marks a session as revoked
func (s *SessionStore) RevokeSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil
	}

	now := time.Now()
	session.Revoked = true
	session.RevokedAt = &now

	return nil
}

// ListUserSessions returns all sessions for a given subject
func (s *SessionStore) ListUserSessions(subject string) []*SessionToken {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var userSessions []*SessionToken
	for _, session := range s.sessions {
		if session.Subject == subject {
			userSessions = append(userSessions, session)
		}
	}

	return userSessions
}

// IsRevoked checks if a session is revoked
func (s *SessionStore) IsRevoked(sessionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return false
	}

	return session.Revoked
}

// CleanupExpired removes expired sessions from storage
func (s *SessionStore) CleanupExpired() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0

	for sessionID, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, sessionID)
			delete(s.byTokenID, session.TokenID)
			removed++
		}
	}

	return removed
}
