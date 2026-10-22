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

func TestRefreshTokenStore_constructor_rejects_corrupt_JSON(t *testing.T) {
	// Given
	path := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(path, "corrupt.json"), []byte("{"), 0o600))

	// When
	_, err := NewRefreshTokenStore(path)

	// Then
	require.Error(t, err)
}

func TestRefreshTokenStore_constructor_loads_legacy_family_as_generation_zero(t *testing.T) {
	// Given
	path := t.TempDir()
	legacy := &RefreshTokenFamily{FamilyID: "legacy", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(time.Hour)}
	data, err := json.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, "legacy.json"), data, 0o600))

	// When
	store, err := NewRefreshTokenStore(path)

	// Then
	require.NoError(t, err)
	family, err := store.GetFamily("legacy")
	require.NoError(t, err)
	require.Empty(t, family.ConsumedGenerationHashes)
}

func TestRefreshTokenStore_RotateOrRevoke_revokes_family_on_consumed_generation_replay(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
	require.NoError(t, rotateFamily(store, "current", "successor", now))

	// When
	_, err = store.RotateOrRevoke("current", "ignored", now)

	// Then
	require.ErrorIs(t, err, ErrRefreshTokenReplay)
	family, getErr := store.GetFamily("family")
	require.NoError(t, getErr)
	require.NotNil(t, family.ReplayDetectedAt)
	require.NotNil(t, family.RevokedAt)
	_, err = store.RotateOrRevoke("successor", "another", now)
	require.ErrorIs(t, err, ErrRefreshTokenRevoked)
}

func TestRefreshTokenStore_RotateOrRevoke_revokes_after_concurrent_rotate_and_replay(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, successor := range []string{"one", "two"} {
		workers.Add(1)
		go func(next string) {
			defer workers.Done()
			<-start
			_, rotateErr := store.RotateOrRevoke("current", next, now)
			results <- rotateErr
		}(successor)
	}

	// When
	close(start)
	workers.Wait()
	close(results)

	// Then
	successes := 0
	for result := range results {
		if result == nil {
			successes++
		} else {
			require.ErrorIs(t, result, ErrRefreshTokenReplay)
		}
	}
	require.Equal(t, 1, successes)
	family, err := store.GetFamily("family")
	require.NoError(t, err)
	require.NotNil(t, family.RevokedAt)
}

func TestRefreshTokenStore_RotateOrRevoke_does_not_publish_on_write_failure(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
	original := atomicJSONWrite
	atomicJSONWrite = func(string, any) (bool, error) { return false, errors.New("write failed") }
	t.Cleanup(func() { atomicJSONWrite = original })

	// When
	_, err = store.RotateOrRevoke("current", "successor", now)

	// Then
	require.Error(t, err)
	family, getErr := store.GetFamily("family")
	require.NoError(t, getErr)
	require.Equal(t, "current", family.CurrentTokenHash)
}

func TestRefreshTokenStore_RotateOrRevoke_publishes_successor_on_directory_close_failure(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	now := time.Now()
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
	closeErr := errors.New("directory close failed")
	originalOpen := openAtomicJSONDir
	openAtomicJSONDir = func(string) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openAtomicJSONDir = originalOpen })

	// When
	_, err = store.RotateOrRevoke("current", "successor", now)

	// Then
	require.ErrorIs(t, err, closeErr)
	family, getErr := store.GetFamily("family")
	require.NoError(t, getErr)
	require.Equal(t, "successor", family.CurrentTokenHash)
	_, err = store.RotateOrRevoke("current", "other", now)
	require.ErrorIs(t, err, ErrRefreshTokenReplay)
}

func TestRefreshTokenStore_SaveFamily_rejects_duplicate_ID(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	expiresAt := time.Now().Add(time.Hour)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "first", ExpiresAt: expiresAt}))

	// When
	err = store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "second", ExpiresAt: expiresAt})

	// Then
	require.ErrorIs(t, err, ErrRefreshTokenFamilyExists)
	family, getErr := store.GetFamily("family")
	require.NoError(t, getErr)
	require.Equal(t, "first", family.CurrentTokenHash)
}

func TestRefreshTokenStore_consumed_generation_lookup_survives_restart(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
	require.NoError(t, rotateFamily(store, "current", "successor", now))

	// When
	reopened, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	family, err := reopened.GetFamilyByTokenHash("current")

	// Then
	require.NoError(t, err)
	require.Equal(t, "family", family.FamilyID)
	_, err = reopened.RotateOrRevoke("current", "ignored", now)
	require.ErrorIs(t, err, ErrRefreshTokenReplay)
}

func TestRefreshTokenStore_GetFamily_returns_defensive_copy(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(time.Hour), Scopes: []string{"read"}}))

	// When
	family, err := store.GetFamily("family")
	require.NoError(t, err)
	family.Scopes[0] = "mutated"
	reloaded, err := store.GetFamily("family")

	// Then
	require.NoError(t, err)
	require.Equal(t, "read", reloaded.Scopes[0])
}

func TestRefreshTokenStore_SaveFamily_rejects_duplicate_generation_hash(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)

	// When
	err = store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ConsumedGenerationHashes: []string{"current"}, ExpiresAt: time.Now().Add(time.Hour)})

	// Then
	require.Error(t, err)
}

func TestRefreshTokenStore_SaveFamily_rejects_generation_hash_owned_by_another_family(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	expiresAt := time.Now().Add(time.Hour)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "first", CurrentTokenHash: "first-current", ExpiresAt: expiresAt}))

	// When
	err = store.SaveFamily(&RefreshTokenFamily{FamilyID: "second", CurrentTokenHash: "second-current", ConsumedGenerationHashes: []string{"first-current"}, ExpiresAt: expiresAt})

	// Then
	require.Error(t, err)
}

func TestRefreshTokenStore_RotateOrRevoke_returns_typed_unknown_outcome(t *testing.T) {
	// Given
	store, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)

	// When
	_, err = store.RotateOrRevoke("unknown", "successor", time.Now())

	// Then
	require.ErrorIs(t, err, ErrRefreshTokenUnknown)
}

func rotateFamily(store *RefreshTokenStore, current, successor string, now time.Time) error {
	_, err := store.RotateOrRevoke(current, successor, now)
	return err
}
