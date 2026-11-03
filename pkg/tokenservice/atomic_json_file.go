package tokenservice

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

type namedAtomicJSONFile struct {
	atomicJSONFile
	name string
}

func (f namedAtomicJSONFile) Name() string { return f.name }

type CommittedWriteError struct{ Err error }

func (e *CommittedWriteError) Error() string   { return e.Err.Error() }
func (e *CommittedWriteError) Unwrap() error   { return e.Err }
func (e *CommittedWriteError) Committed() bool { return true }

var (
	atomicJSONWrite      = writeAtomicJSON
	createAtomicJSONTemp = createStoreTemp
	renameAtomicJSONFile = func(root *storeRoot, oldName, newName string) error { return root.root.Rename(oldName, newName) }
	removeAtomicJSONFile = func(root *storeRoot, name string) error { return root.root.Remove(name) }
	openAtomicJSONDir    = func(root *storeRoot) (directorySyncer, error) { return root.root.Open(".") }
	openStoreDirectory   = func(directory string) (directorySyncer, error) { return os.Open(directory) }
)

func createStoreTemp(root *storeRoot, _ string) (atomicJSONFile, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("random temporary JSON name: %w", err)
	}
	name := ".tmp-" + hex.EncodeToString(random[:])
	file, err := root.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return namedAtomicJSONFile{atomicJSONFile: file, name: name}, nil
}

func writeAtomicJSON(root *storeRoot, name string, value any) (bool, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal JSON: %w", err)
	}
	name, err = safeStoreBasename(name)
	if err != nil {
		return false, err
	}
	temporary, err := createAtomicJSONTemp(root, ".tmp-*")
	if err != nil {
		return false, fmt.Errorf("create temporary JSON file: %w", err)
	}
	temporaryName := temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		return false, closeAndRemoveTemporary(root, temporary, temporaryName, fmt.Errorf("set temporary JSON file permissions: %w", err))
	}
	if _, err := temporary.Write(data); err != nil {
		return false, closeAndRemoveTemporary(root, temporary, temporaryName, fmt.Errorf("write temporary JSON file: %w", err))
	}
	if err := temporary.Sync(); err != nil {
		return false, closeAndRemoveTemporary(root, temporary, temporaryName, fmt.Errorf("sync temporary JSON file: %w", err))
	}
	if err := temporary.Close(); err != nil {
		return false, removeTemporary(root, temporaryName, fmt.Errorf("close temporary JSON file: %w", err))
	}
	if err := renameAtomicJSONFile(root, temporaryName, name); err != nil {
		return false, removeTemporary(root, temporaryName, fmt.Errorf("rename temporary JSON file: %w", err))
	}
	if err := syncAndCloseRootDirectory(openAtomicJSONDir, root, "JSON"); err != nil {
		return true, &CommittedWriteError{Err: err}
	}
	return true, nil
}

func closeAndRemoveTemporary(root *storeRoot, file atomicJSONFile, name string, primary error) error {
	return removeTemporary(root, name, errors.Join(primary, closeAtomicJSONFile(file)))
}

func closeAtomicJSONFile(file atomicJSONFile) error {
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary JSON file: %w", err)
	}
	return nil
}

func removeTemporary(root *storeRoot, name string, primary error) error {
	if err := removeAtomicJSONFile(root, name); err != nil {
		return errors.Join(primary, fmt.Errorf("remove temporary JSON file: %w", err))
	}
	return primary
}

func syncAndCloseRootDirectory(open func(*storeRoot) (directorySyncer, error), root *storeRoot, kind string) error {
	directory, err := open(root)
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
