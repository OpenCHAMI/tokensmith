package tokenservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenStoreRoot_rejects_symlinked_root(t *testing.T) {
	// Given
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	path := filepath.Join(parent, "store")
	require.NoError(t, os.Symlink(target, path))

	// When
	root, err := openStoreRoot(path)

	// Then
	require.Error(t, err)
	require.Nil(t, root)
}

func TestOpenStoreRoot_rejects_non_directory_root(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	// When
	root, err := openStoreRoot(path)

	// Then
	require.Error(t, err)
	require.Nil(t, root)
}

func TestStoreRoot_ReadRecord_rejects_symlink(t *testing.T) {
	// Given
	root, err := openStoreRoot(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	target := filepath.Join(t.TempDir(), "record.json")
	require.NoError(t, os.WriteFile(target, []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(root.path, "record.json")))

	// When
	_, err = root.ReadRecord("record.json")

	// Then
	require.Error(t, err)
}

func TestOpenStoreRoot_rejects_substitution_between_validation_and_open(t *testing.T) {
	// Given
	configured := filepath.Join(t.TempDir(), "configured")
	attacker := t.TempDir()
	require.NoError(t, os.Mkdir(configured, 0o700))
	original := beforeOpenStoreRoot
	beforeOpenStoreRoot = func() {
		require.NoError(t, os.Rename(configured, configured+"-original"))
		require.NoError(t, os.Symlink(attacker, configured))
	}
	t.Cleanup(func() { beforeOpenStoreRoot = original })

	// When
	root, err := openStoreRoot(configured)

	// Then
	require.ErrorContains(t, err, "changed before opening")
	require.Nil(t, root)
}
