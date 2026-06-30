// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"sync"
	"time"
)

// RevocationStore maintains an in-memory blocklist of revoked JWT IDs (JTIs).
// Per RFC 7009 (OAuth 2.0 Token Revocation), revoked tokens remain invalid
// until their original expiration time. This implementation stores JTIs with
// their expiry timestamps and automatically prunes expired entries.
//
// Thread-safe for concurrent access.
type RevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

// NewRevocationStore creates a new empty revocation store.
func NewRevocationStore() *RevocationStore {
	return &RevocationStore{
		revoked: make(map[string]time.Time),
	}
}

// Revoke adds a JWT ID (JTI) to the revocation blocklist.
// The JTI remains revoked until the specified expiry time.
// Multiple calls with the same JTI update the expiry time.
func (r *RevocationStore) Revoke(jti string, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[jti] = expiresAt
}

// IsRevoked checks if a JWT ID (JTI) is in the revocation blocklist.
// Returns true if the JTI is revoked and has not expired yet.
// Automatically prunes expired entries during the check.
func (r *RevocationStore) IsRevoked(jti string) bool {
	r.mu.RLock()
	expiresAt, exists := r.revoked[jti]
	r.mu.RUnlock()

	if !exists {
		return false
	}

	now := time.Now()
	if now.After(expiresAt) {
		r.mu.Lock()
		delete(r.revoked, jti)
		r.mu.Unlock()
		return false
	}

	return true
}

// Prune removes all expired entries from the revocation store.
// This is called periodically to prevent memory growth.
// Returns the number of entries removed.
func (r *RevocationStore) Prune() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	removed := 0

	for jti, expiresAt := range r.revoked {
		if now.After(expiresAt) {
			delete(r.revoked, jti)
			removed++
		}
	}

	return removed
}

// Size returns the current number of revoked tokens in the store.
// This includes both active and expired entries.
func (r *RevocationStore) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.revoked)
}
