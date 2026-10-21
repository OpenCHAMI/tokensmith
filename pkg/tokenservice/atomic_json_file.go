package tokenservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type atomicJSONFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type directorySyncer interface {
	Sync() error
	Close() error
}

type CommittedWriteError struct{ Err error }

func (e *CommittedWriteError) Error() string   { return e.Err.Error() }
func (e *CommittedWriteError) Unwrap() error   { return e.Err }
func (e *CommittedWriteError) Committed() bool { return true }

var (
	atomicJSONWrite      = writeAtomicJSON
	createAtomicJSONTemp = func(directory, pattern string) (atomicJSONFile, error) { return os.CreateTemp(directory, pattern) }
	renameAtomicJSONFile = os.Rename
	removeAtomicJSONFile = os.Remove
	openAtomicJSONDir    = func(directory string) (directorySyncer, error) { return os.Open(directory) }
	openStoreDirectory   = func(directory string) (directorySyncer, error) { return os.Open(directory) }
)

func writeAtomicJSON(path string, value any) (bool, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal JSON: %w", err)
	}
	temporary, err := createAtomicJSONTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temporary JSON file: %w", err)
	}
	temporaryPath := temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		return false, closeAndRemoveTemporary(temporary, temporaryPath, fmt.Errorf("set temporary JSON file permissions: %w", err))
	}
	if _, err := temporary.Write(data); err != nil {
		return false, closeAndRemoveTemporary(temporary, temporaryPath, fmt.Errorf("write temporary JSON file: %w", err))
	}
	if err := temporary.Sync(); err != nil {
		return false, closeAndRemoveTemporary(temporary, temporaryPath, fmt.Errorf("sync temporary JSON file: %w", err))
	}
	if err := temporary.Close(); err != nil {
		return false, removeTemporary(temporaryPath, fmt.Errorf("close temporary JSON file: %w", err))
	}
	if err := renameAtomicJSONFile(temporaryPath, path); err != nil {
		return false, removeTemporary(temporaryPath, fmt.Errorf("rename temporary JSON file: %w", err))
	}
	err = syncAndCloseDirectory(openAtomicJSONDir, filepath.Dir(path), "JSON")
	if err != nil {
		return true, &CommittedWriteError{Err: err}
	}
	return true, nil
}

func closeAndRemoveTemporary(file atomicJSONFile, path string, primary error) error {
	return removeTemporary(path, errors.Join(primary, closeAtomicJSONFile(file)))
}

func closeAtomicJSONFile(file atomicJSONFile) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary JSON file: %w", err)
	}
	return nil
}

func removeTemporary(path string, primary error) error {
	if err := removeAtomicJSONFile(path); err != nil {
		return errors.Join(primary, fmt.Errorf("remove temporary JSON file: %w", err))
	}
	return primary
}

func syncAndCloseDirectory(open func(string) (directorySyncer, error), path, kind string) error {
	directory, err := open(path)
	if err != nil {
		return fmt.Errorf("open %s directory: %w", kind, err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(wrapDirectoryError(kind, "sync", syncErr), wrapDirectoryError(kind, "close", closeErr))
	}
	return nil
}

func wrapDirectoryError(kind, operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s directory: %w", operation, kind, err)
}
