package tokenservice

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteAtomicJSON_returns_close_failure_without_publishing(t *testing.T) {
	// Given
	directory := t.TempDir()
	destination := filepath.Join(directory, "policy.json")
	root, err := openStoreRoot(directory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	closeErr := errors.New("close failed")
	file, err := root.root.OpenFile(".tmp-test", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	require.NoError(t, err)
	originalCreate := createAtomicJSONTemp
	createAtomicJSONTemp = func(*storeRoot, string) (atomicJSONFile, error) {
		return namedAtomicJSONFile{atomicJSONFile: closeFailingAtomicFile{File: file, closeErr: closeErr}, name: ".tmp-test"}, nil
	}
	t.Cleanup(func() { createAtomicJSONTemp = originalCreate })

	// When
	_, err = writeAtomicJSON(root, "policy.json", map[string]string{"key": "value"})

	// Then
	require.ErrorIs(t, err, closeErr)
	_, statErr := os.Stat(destination)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}

func TestWriteAtomicJSON_returns_primary_and_temp_removal_failures(t *testing.T) {
	// Given
	directory := t.TempDir()
	destination := filepath.Join(directory, "policy.json")
	root, err := openStoreRoot(directory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	syncErr := errors.New("sync failed")
	removeErr := errors.New("remove failed")
	file, err := root.root.OpenFile(".tmp-test", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.Remove(file.Name())) })
	originalCreate := createAtomicJSONTemp
	originalRemove := removeAtomicJSONFile
	createAtomicJSONTemp = func(*storeRoot, string) (atomicJSONFile, error) {
		return namedAtomicJSONFile{atomicJSONFile: syncFailingAtomicFile{File: file, syncErr: syncErr}, name: ".tmp-test"}, nil
	}
	removeAtomicJSONFile = func(*storeRoot, string) error { return removeErr }
	t.Cleanup(func() { createAtomicJSONTemp = originalCreate; removeAtomicJSONFile = originalRemove })

	// When
	_, err = writeAtomicJSON(root, "policy.json", map[string]string{"key": "value"})

	// Then
	require.ErrorIs(t, err, syncErr)
	require.ErrorIs(t, err, removeErr)
	_, statErr := os.Stat(destination)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	_, statErr = os.Stat(file.Name())
	require.NoError(t, statErr)
}

func TestWriteAtomicJSON_returns_directory_close_failure_after_rename(t *testing.T) {
	// Given
	directory := t.TempDir()
	destination := filepath.Join(directory, "policy.json")
	root, err := openStoreRoot(directory)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	closeErr := errors.New("directory close failed")
	originalOpen := openAtomicJSONDir
	openAtomicJSONDir = func(*storeRoot) (directorySyncer, error) { return failingDirectory{closeErr: closeErr}, nil }
	t.Cleanup(func() { openAtomicJSONDir = originalOpen })

	// When
	committed, err := writeAtomicJSON(root, "policy.json", map[string]string{"key": "value"})

	// Then
	require.ErrorIs(t, err, closeErr)
	require.True(t, committed)
	_, statErr := os.Stat(destination)
	require.NoError(t, statErr)
}

type closeFailingAtomicFile struct {
	*os.File
	closeErr error
}

func (f closeFailingAtomicFile) Close() error {
	if err := f.File.Close(); err != nil {
		return err
	}
	return f.closeErr
}

type syncFailingAtomicFile struct {
	*os.File
	syncErr error
}

func (f syncFailingAtomicFile) Sync() error { return f.syncErr }

type failingDirectory struct {
	syncErr  error
	closeErr error
}

func (d failingDirectory) Sync() error  { return d.syncErr }
func (d failingDirectory) Close() error { return d.closeErr }
