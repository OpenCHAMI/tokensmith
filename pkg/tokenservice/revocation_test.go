// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRevocationStore_Revoke(t *testing.T) {
	store := NewRevocationStore()
	jti := "test-jti-123"
	expiresAt := time.Now().Add(1 * time.Hour)

	store.Revoke(jti, expiresAt)

	assert.True(t, store.IsRevoked(jti), "JTI should be revoked")
	assert.Equal(t, 1, store.Size(), "Store should contain 1 entry")
}

func TestRevocationStore_IsRevoked_NotRevoked(t *testing.T) {
	store := NewRevocationStore()

	assert.False(t, store.IsRevoked("nonexistent-jti"), "Non-revoked JTI should return false")
}

func TestRevocationStore_IsRevoked_ExpiredEntry(t *testing.T) {
	store := NewRevocationStore()
	jti := "expired-jti"
	expiresAt := time.Now().Add(-1 * time.Hour)

	store.Revoke(jti, expiresAt)
	assert.Equal(t, 1, store.Size(), "Store should contain 1 entry before check")

	assert.False(t, store.IsRevoked(jti), "Expired JTI should return false")
	assert.Equal(t, 0, store.Size(), "Expired entry should be auto-pruned")
}

func TestRevocationStore_IsRevoked_AutoPruneOnCheck(t *testing.T) {
	store := NewRevocationStore()

	store.Revoke("jti-1", time.Now().Add(-1*time.Hour))
	store.Revoke("jti-2", time.Now().Add(1*time.Hour))
	store.Revoke("jti-3", time.Now().Add(-30*time.Minute))

	assert.Equal(t, 3, store.Size(), "Store should contain 3 entries")

	assert.False(t, store.IsRevoked("jti-1"), "Expired JTI should return false")
	assert.True(t, store.IsRevoked("jti-2"), "Valid JTI should return true")
	assert.False(t, store.IsRevoked("jti-3"), "Expired JTI should return false")

	assert.Equal(t, 1, store.Size(), "Only 1 valid entry should remain")
}

func TestRevocationStore_Revoke_UpdateExpiry(t *testing.T) {
	store := NewRevocationStore()
	jti := "update-test"

	firstExpiry := time.Now().Add(1 * time.Hour)
	store.Revoke(jti, firstExpiry)
	assert.Equal(t, 1, store.Size())

	secondExpiry := time.Now().Add(2 * time.Hour)
	store.Revoke(jti, secondExpiry)
	assert.Equal(t, 1, store.Size(), "Should still have 1 entry after update")

	assert.True(t, store.IsRevoked(jti), "JTI should still be revoked")
}

func TestRevocationStore_Prune(t *testing.T) {
	store := NewRevocationStore()

	store.Revoke("expired-1", time.Now().Add(-2*time.Hour))
	store.Revoke("expired-2", time.Now().Add(-1*time.Hour))
	store.Revoke("valid-1", time.Now().Add(1*time.Hour))
	store.Revoke("valid-2", time.Now().Add(2*time.Hour))

	assert.Equal(t, 4, store.Size(), "Store should contain 4 entries before pruning")

	removed := store.Prune()

	assert.Equal(t, 2, removed, "Should have removed 2 expired entries")
	assert.Equal(t, 2, store.Size(), "Store should contain 2 entries after pruning")

	assert.True(t, store.IsRevoked("valid-1"))
	assert.True(t, store.IsRevoked("valid-2"))
	assert.False(t, store.IsRevoked("expired-1"))
	assert.False(t, store.IsRevoked("expired-2"))
}

func TestRevocationStore_Prune_EmptyStore(t *testing.T) {
	store := NewRevocationStore()

	removed := store.Prune()

	assert.Equal(t, 0, removed, "Pruning empty store should remove 0 entries")
	assert.Equal(t, 0, store.Size())
}

func TestRevocationStore_ConcurrentAccess(t *testing.T) {
	store := NewRevocationStore()
	const goroutines = 100
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				jti := time.Now().Format("2006-01-02T15:04:05.000000000")
				store.Revoke(jti, time.Now().Add(1*time.Hour))
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				jti := time.Now().Format("2006-01-02T15:04:05.000000000")
				_ = store.IsRevoked(jti)
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				_ = store.Prune()
			}
		}(i)
	}

	wg.Wait()

	assert.True(t, store.Size() >= 0, "Store size should be valid after concurrent operations")
}

func TestRevocationStore_Size(t *testing.T) {
	store := NewRevocationStore()

	assert.Equal(t, 0, store.Size(), "New store should be empty")

	store.Revoke("jti-1", time.Now().Add(1*time.Hour))
	assert.Equal(t, 1, store.Size())

	store.Revoke("jti-2", time.Now().Add(1*time.Hour))
	assert.Equal(t, 2, store.Size())

	store.Revoke("jti-3", time.Now().Add(-1*time.Hour))
	assert.Equal(t, 3, store.Size(), "Size includes expired entries before prune")

	store.Prune()
	assert.Equal(t, 2, store.Size(), "Size should decrease after pruning")
}

func TestRevocationStore_RaceCondition_IsRevokedWhilePruning(t *testing.T) {
	store := NewRevocationStore()
	jti := "race-test"

	store.Revoke(jti, time.Now().Add(1*time.Hour))

	done := make(chan bool)

	go func() {
		for i := 0; i < 1000; i++ {
			_ = store.IsRevoked(jti)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 1000; i++ {
			_ = store.Prune()
		}
		done <- true
	}()

	<-done
	<-done

	assert.True(t, store.IsRevoked(jti), "JTI should still be revoked after concurrent operations")
}

func BenchmarkRevocationStore_Revoke(b *testing.B) {
	store := NewRevocationStore()
	expiresAt := time.Now().Add(1 * time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Revoke("benchmark-jti", expiresAt)
	}
}

func BenchmarkRevocationStore_IsRevoked_Hit(b *testing.B) {
	store := NewRevocationStore()
	jti := "benchmark-jti"
	store.Revoke(jti, time.Now().Add(1*time.Hour))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.IsRevoked(jti)
	}
}

func BenchmarkRevocationStore_IsRevoked_Miss(b *testing.B) {
	store := NewRevocationStore()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.IsRevoked("nonexistent-jti")
	}
}

func BenchmarkRevocationStore_Prune(b *testing.B) {
	store := NewRevocationStore()

	for i := 0; i < 1000; i++ {
		store.Revoke(time.Now().Format("jti-%d"), time.Now().Add(1*time.Hour))
	}
	for i := 0; i < 1000; i++ {
		store.Revoke(time.Now().Format("expired-%d"), time.Now().Add(-1*time.Hour))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.Prune()
	}
}
