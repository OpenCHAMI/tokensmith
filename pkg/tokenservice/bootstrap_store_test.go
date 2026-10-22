package tokenservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBootstrapTokenStore_constructor_rejects_corrupt_JSON(t *testing.T) {
	// Given
	path := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(path, "corrupt.json"), []byte("{"), 0o600))

	// When
	_, err := NewBootstrapTokenStore(path)

	// Then
	require.Error(t, err)
}

func TestBootstrapTokenStore_ConsumePolicy_allows_exactly_one_concurrent_consumer(t *testing.T) {
	// Given
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	hash := HashBootstrapToken("bootstrap")
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "policy", TokenHash: hash, ExpiresAt: now.Add(time.Hour)}))

	// When
	const workers = 20
	start := make(chan struct{})
	results := make(chan error, workers)
	var workersDone sync.WaitGroup
	for range workers {
		workersDone.Add(1)
		go func() {
			defer workersDone.Done()
			<-start
			_, consumeErr := store.ConsumePolicy(hash, "127.0.0.1", now)
			results <- consumeErr
		}()
	}
	close(start)
	workersDone.Wait()
	close(results)

	// Then
	winners := 0
	for result := range results {
		if result == nil {
			winners++
			continue
		}
		require.ErrorIs(t, result, ErrBootstrapTokenConsumed)
	}
	require.Equal(t, 1, winners)
}

func TestBootstrapTokenStore_ConsumePolicy_rejects_expired_policy(t *testing.T) {
	// Given
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	hash := HashBootstrapToken("expired")
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "expired", TokenHash: hash, ExpiresAt: now.Add(-time.Second)}))

	// When
	_, err = store.ConsumePolicy(hash, "127.0.0.1", now)

	// Then
	require.ErrorIs(t, err, ErrBootstrapTokenExpired)
}

func TestBootstrapTokenStore_ConsumePolicy_persists_consumption_across_restart(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	hash := HashBootstrapToken("restart")
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "restart", TokenHash: hash, ExpiresAt: now.Add(time.Hour)}))
	require.NoError(t, consumePolicy(store, hash, now))

	// When
	reopened, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	_, err = reopened.ConsumePolicy(hash, "127.0.0.2", now)

	// Then
	require.ErrorIs(t, err, ErrBootstrapTokenConsumed)
}

func consumePolicy(store *BootstrapTokenStore, hash string, now time.Time) error {
	_, err := store.ConsumePolicy(hash, "127.0.0.1", now)
	return err
}

func TestBootstrapTokenStore_GetPolicy_returns_defensive_copy(t *testing.T) {
	// Given
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	hash := HashBootstrapToken("copy")
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "copy", TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour), Scopes: []string{"read"}}))

	// When
	policy, err := store.GetPolicy(hash)
	require.NoError(t, err)
	policy.Scopes[0] = "mutated"
	policy.Subject = "mutated"
	reloaded, err := store.GetPolicy(hash)

	// Then
	require.NoError(t, err)
	require.Equal(t, "read", reloaded.Scopes[0])
	require.Empty(t, reloaded.Subject)
}

func TestBootstrapTokenStore_ConsumePolicy_does_not_publish_on_write_failure(t *testing.T) {
	// Given
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	hash := HashBootstrapToken("write-failure")
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "write", TokenHash: hash, ExpiresAt: now.Add(time.Hour)}))
	original := atomicJSONWrite
	atomicJSONWrite = func(string, any) (bool, error) { return false, errors.New("write failed") }
	t.Cleanup(func() { atomicJSONWrite = original })

	// When
	_, err = store.ConsumePolicy(hash, "127.0.0.1", now)

	// Then
	require.Error(t, err)
	policy, getErr := store.GetPolicy(hash)
	require.NoError(t, getErr)
	require.Nil(t, policy.ConsumedAt)
}

func TestBootstrapTokenStore_ConsumePolicy_publishes_committed_state_on_directory_close_failure(t *testing.T) {
	// Given
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Now()
	policy := &BootstrapTokenPolicy{ID: "close", TokenHash: HashBootstrapToken("close"), ExpiresAt: now.Add(time.Hour)}
	require.NoError(t, store.SavePolicy(policy))
	closeErr := errors.New("directory close failed")
	originalOpen := openAtomicJSONDir
	openAtomicJSONDir = func(string) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openAtomicJSONDir = originalOpen })

	// When
	_, err = store.ConsumePolicy(policy.TokenHash, "127.0.0.1", now)

	// Then
	require.ErrorIs(t, err, closeErr)
	consumed, getErr := store.GetPolicy(policy.TokenHash)
	require.NoError(t, getErr)
	require.NotNil(t, consumed.ConsumedAt)
	_, err = store.ConsumePolicy(policy.TokenHash, "127.0.0.1", now)
	require.ErrorIs(t, err, ErrBootstrapTokenConsumed)
}

func TestBootstrapTokenStore_constructor_loads_legacy_JSON(t *testing.T) {
	// Given
	path := t.TempDir()
	hash := HashBootstrapToken("legacy")
	legacy := &BootstrapTokenPolicy{ID: "legacy", TokenHash: hash, ExpiresAt: time.Now().Add(time.Hour)}
	data, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, hash+".json"), data, 0o600))

	// When
	store, err := NewBootstrapTokenStore(path)

	// Then
	require.NoError(t, err)
	policy, err := store.GetPolicy(hash)
	require.NoError(t, err)
	require.Equal(t, "legacy", policy.ID)
}

func TestBootstrapTokenStore_SavePolicy_rejects_duplicate_identity(t *testing.T) {
	// Given
	store, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Now().Add(time.Hour)
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "same", TokenHash: "first", ExpiresAt: now}))

	// When
	err = store.SavePolicy(&BootstrapTokenPolicy{ID: "same", TokenHash: "second", ExpiresAt: now})

	// Then
	require.Error(t, err)
}
