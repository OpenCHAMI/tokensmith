// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePolicyFileForTest(t *testing.T, storePath string, policy *BootstrapTokenPolicy) {
	t.Helper()

	filePath := filepath.Join(storePath, policy.TokenHash+".json")
	data, err := json.MarshalIndent(policy, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filePath, data, 0600))
}

func TestBootstrapTokenStore_GetPolicy_FallbackToDiskAndCache(t *testing.T) {
	storePath := t.TempDir()
	store, err := NewBootstrapTokenStore(storePath)
	require.NoError(t, err)

	tokenHash := HashBootstrapToken("opaque-token-value")
	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-1",
		Subject:    "boot-service",
		Audience:   "smd",
		TokenHash:  tokenHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}

	// Simulate policy created after store startup by another process.
	writePolicyFileForTest(t, storePath, policy)

	loaded, err := store.GetPolicy(tokenHash)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, policy.Subject, loaded.Subject)
	assert.Equal(t, policy.TokenHash, loaded.TokenHash)

	// Ensure it was cached in-memory and no longer depends on disk file.
	require.NoError(t, os.Remove(filepath.Join(storePath, tokenHash+".json")))
	cached, err := store.GetPolicy(tokenHash)
	require.NoError(t, err)
	assert.Equal(t, tokenHash, cached.TokenHash)
}

func TestBootstrapTokenStore_GetPolicy_NotFound(t *testing.T) {
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)

	_, err = store.GetPolicy(HashBootstrapToken("missing"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestBootstrapTokenStore_GetPolicy_InvalidJSON(t *testing.T) {
	storePath := t.TempDir()
	store, err := NewBootstrapTokenStore(storePath)
	require.NoError(t, err)

	tokenHash := HashBootstrapToken("invalid-json")
	filePath := filepath.Join(storePath, tokenHash+".json")
	require.NoError(t, os.WriteFile(filePath, []byte("{not valid json"), 0600))

	_, err = store.GetPolicy(tokenHash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal bootstrap policy file")
}

func TestBootstrapTokenStore_GetPolicy_HashMismatch(t *testing.T) {
	storePath := t.TempDir()
	store, err := NewBootstrapTokenStore(storePath)
	require.NoError(t, err)

	expectedHash := HashBootstrapToken("expected-token")
	wrongHash := HashBootstrapToken("wrong-token")
	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-mismatch",
		Subject:    "boot-service",
		Audience:   "smd",
		TokenHash:  wrongHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}

	filePath := filepath.Join(storePath, expectedHash+".json")
	data, err := json.MarshalIndent(policy, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	_, err = store.GetPolicy(expectedHash)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap token hash mismatch")
}

func TestBootstrapTokenStore_GetPolicy_ConcurrentFallback(t *testing.T) {
	storePath := t.TempDir()
	store, err := NewBootstrapTokenStore(storePath)
	require.NoError(t, err)

	tokenHash := HashBootstrapToken("concurrent-token")
	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-concurrent",
		Subject:    "boot-service",
		Audience:   "smd",
		TokenHash:  tokenHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	writePolicyFileForTest(t, storePath, policy)

	const workers = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, getErr := store.GetPolicy(tokenHash)
			if getErr != nil {
				errCh <- fmt.Errorf("worker %d: %w", i, getErr)
				return
			}
			if p == nil || p.TokenHash != tokenHash {
				errCh <- fmt.Errorf("worker %d: invalid policy", i)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for callErr := range errCh {
		require.NoError(t, callErr)
	}
}
