package tokenservice

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRemoveStoreFile_returns_directory_close_failure(t *testing.T) {
	// Given
	directory := t.TempDir()
	path := filepath.Join(directory, "expired.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	root, err := openStoreRoot(directory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	closeErr := errors.New("directory close failed")
	originalOpen := openStoreDirectory
	openStoreDirectory = func(*storeRoot) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openStoreDirectory = originalOpen })

	// When
	committed, err := removeStoreFile(root, "expired")

	// Then
	require.True(t, committed)
	require.ErrorIs(t, err, closeErr)
	require.True(t, committedWriteWarning(err))
	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestBootstrapTokenStore_CleanupExpired_waits_for_store_flock(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "expired", TokenHash: "expired", ExpiresAt: time.Now().Add(-time.Hour)}))
	release := holdStoreLock(t, path)
	originalBeforeFlock := beforeStoreFlock
	attempted := make(chan struct{})
	beforeStoreFlock = func() { attempted <- struct{}{} }
	t.Cleanup(func() { beforeStoreFlock = originalBeforeFlock })
	originalProcs := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(originalProcs) })
	completed := make(chan error, 1)

	// When
	go func() { completed <- store.CleanupExpired() }()

	// Then
	<-attempted
	runtime.Gosched()
	require.Empty(t, completed)
	release()
	require.NoError(t, <-completed)
}

func TestRefreshTokenStore_CleanupExpired_waits_for_store_flock(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "expired", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(-time.Hour)}))
	release := holdStoreLock(t, path)
	originalBeforeFlock := beforeStoreFlock
	attempted := make(chan struct{})
	beforeStoreFlock = func() { attempted <- struct{}{} }
	t.Cleanup(func() { beforeStoreFlock = originalBeforeFlock })
	originalProcs := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(originalProcs) })
	completed := make(chan error, 1)

	// When
	go func() { completed <- store.CleanupExpired() }()

	// Then
	<-attempted
	runtime.Gosched()
	require.Empty(t, completed)
	release()
	require.NoError(t, <-completed)
}

func TestBootstrapTokenStore_CleanupExpired_reloads_before_removing_stale_entry(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	policy := &BootstrapTokenPolicy{ID: "policy", TokenHash: "policy", ExpiresAt: time.Now().Add(-time.Hour)}
	require.NoError(t, store.SavePolicy(policy))
	policy.ExpiresAt = time.Now().Add(time.Hour)
	committed, err := atomicJSONWrite(store.root, policy.TokenHash+".json", policyToDisk(policy))
	require.NoError(t, err)
	require.True(t, committed)

	// When
	err = store.CleanupExpired()

	// Then
	require.NoError(t, err)
	reloaded, err := store.GetPolicy(policy.TokenHash)
	require.NoError(t, err)
	require.True(t, policy.ExpiresAt.Equal(reloaded.ExpiresAt))
}

func TestRefreshTokenStore_CleanupExpired_reloads_before_removing_stale_entry(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	family := &RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(-time.Hour)}
	require.NoError(t, store.SaveFamily(family))
	family.ExpiresAt = time.Now().Add(time.Hour)
	committed, err := atomicJSONWrite(store.root, family.FamilyID+".json", familyToDisk(family))
	require.NoError(t, err)
	require.True(t, committed)

	// When
	err = store.CleanupExpired()

	// Then
	require.NoError(t, err)
	reloaded, err := store.GetFamily(family.FamilyID)
	require.NoError(t, err)
	require.True(t, family.ExpiresAt.Equal(reloaded.ExpiresAt))
}

func TestBootstrapTokenStore_CleanupExpired_removes_committed_unlink_after_directory_close_failure(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	policy := &BootstrapTokenPolicy{ID: "expired", TokenHash: "expired", ExpiresAt: time.Now().Add(-time.Hour)}
	require.NoError(t, store.SavePolicy(policy))
	closeErr := errors.New("directory close failed")
	originalOpen := openStoreDirectory
	openStoreDirectory = func(*storeRoot) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openStoreDirectory = originalOpen })

	// When
	err = store.CleanupExpired()

	// Then
	require.ErrorIs(t, err, closeErr)
	require.True(t, committedWriteWarning(err))
	require.NotContains(t, store.policies, policy.TokenHash)
}

func TestRefreshTokenStore_CleanupExpired_removes_committed_unlink_after_directory_close_failure(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	family := &RefreshTokenFamily{FamilyID: "expired", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(-time.Hour)}
	require.NoError(t, store.SaveFamily(family))
	closeErr := errors.New("directory close failed")
	originalOpen := openStoreDirectory
	openStoreDirectory = func(*storeRoot) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openStoreDirectory = originalOpen })

	// When
	err = store.CleanupExpired()

	// Then
	require.ErrorIs(t, err, closeErr)
	require.True(t, committedWriteWarning(err))
	require.NotContains(t, store.families, family.FamilyID)
}
