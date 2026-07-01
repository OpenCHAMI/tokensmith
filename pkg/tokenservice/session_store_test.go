// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionStore(t *testing.T) {
	t.Run("SaveSession stores session by ID and token ID", func(t *testing.T) {
		store := NewSessionStore()
		now := time.Now()

		session := &SessionToken{
			SessionID: "sess-123",
			TokenID:   "tok-456",
			Subject:   "user@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			Revoked:   false,
		}

		err := store.SaveSession(session)
		require.NoError(t, err)

		retrieved, ok := store.GetSessionByID("sess-123")
		require.True(t, ok)
		assert.Equal(t, "sess-123", retrieved.SessionID)
		assert.Equal(t, "tok-456", retrieved.TokenID)

		retrievedByToken, ok := store.GetSessionByTokenID("tok-456")
		require.True(t, ok)
		assert.Equal(t, "sess-123", retrievedByToken.SessionID)
	})

	t.Run("RevokeSession marks session as revoked", func(t *testing.T) {
		store := NewSessionStore()
		now := time.Now()

		session := &SessionToken{
			SessionID: "sess-123",
			TokenID:   "tok-456",
			Subject:   "user@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			Revoked:   false,
		}

		err := store.SaveSession(session)
		require.NoError(t, err)

		assert.False(t, store.IsRevoked("sess-123"))

		err = store.RevokeSession("sess-123")
		require.NoError(t, err)

		assert.True(t, store.IsRevoked("sess-123"))

		retrieved, ok := store.GetSessionByID("sess-123")
		require.True(t, ok)
		assert.True(t, retrieved.Revoked)
		assert.NotNil(t, retrieved.RevokedAt)
	})

	t.Run("ListUserSessions returns all sessions for subject", func(t *testing.T) {
		store := NewSessionStore()
		now := time.Now()

		session1 := &SessionToken{
			SessionID: "sess-1",
			TokenID:   "tok-1",
			Subject:   "user1@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		}
		session2 := &SessionToken{
			SessionID: "sess-2",
			TokenID:   "tok-2",
			Subject:   "user1@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		}
		session3 := &SessionToken{
			SessionID: "sess-3",
			TokenID:   "tok-3",
			Subject:   "user2@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		}

		require.NoError(t, store.SaveSession(session1))
		require.NoError(t, store.SaveSession(session2))
		require.NoError(t, store.SaveSession(session3))

		user1Sessions := store.ListUserSessions("user1@example.com")
		assert.Len(t, user1Sessions, 2)

		user2Sessions := store.ListUserSessions("user2@example.com")
		assert.Len(t, user2Sessions, 1)
	})

	t.Run("CleanupExpired removes expired sessions", func(t *testing.T) {
		store := NewSessionStore()
		now := time.Now()

		activeSession := &SessionToken{
			SessionID: "sess-active",
			TokenID:   "tok-active",
			Subject:   "user@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		}
		expiredSession := &SessionToken{
			SessionID: "sess-expired",
			TokenID:   "tok-expired",
			Subject:   "user@example.com",
			CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-1 * time.Hour),
		}

		require.NoError(t, store.SaveSession(activeSession))
		require.NoError(t, store.SaveSession(expiredSession))

		_, ok := store.GetSessionByID("sess-active")
		assert.True(t, ok)
		_, ok = store.GetSessionByID("sess-expired")
		assert.True(t, ok)

		removed := store.CleanupExpired()
		assert.Equal(t, 1, removed)

		_, ok = store.GetSessionByID("sess-active")
		assert.True(t, ok)
		_, ok = store.GetSessionByID("sess-expired")
		assert.False(t, ok)
	})

	t.Run("RevokeSession on non-existent session is no-op", func(t *testing.T) {
		store := NewSessionStore()

		err := store.RevokeSession("non-existent")
		require.NoError(t, err)

		assert.False(t, store.IsRevoked("non-existent"))
	})
}
