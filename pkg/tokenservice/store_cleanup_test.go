package tokenservice

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveStoreFile_returns_directory_close_failure(t *testing.T) {
	// Given
	directory := t.TempDir()
	path := filepath.Join(directory, "expired.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	closeErr := errors.New("directory close failed")
	originalOpen := openStoreDirectory
	openStoreDirectory = func(string) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openStoreDirectory = originalOpen })

	// When
	err := removeStoreFile(directory, "expired")

	// Then
	require.ErrorIs(t, err, closeErr)
	_, statErr := os.Stat(path)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}
