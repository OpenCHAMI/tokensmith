//go:build darwin || linux

package tokenservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLockStore_rejects_symlinked_lock_file(t *testing.T) {
	// Given
	directory := t.TempDir()
	root, err := openStoreRoot(directory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	target := filepath.Join(t.TempDir(), "target.lock")
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(directory, ".store.lock")))

	// When
	lock, err := lockStore(root)

	// Then
	require.Error(t, err)
	require.Nil(t, lock)
}

func TestStoreRootOwner_rejects_noncurrent_EUID(t *testing.T) {
	// Given
	info, err := os.Lstat(t.TempDir())
	require.NoError(t, err)

	// When
	err = validateStoreRootOwnerForEUID(info, os.Geteuid()+1)

	// Then
	require.Error(t, err)
}
