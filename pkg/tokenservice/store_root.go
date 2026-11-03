package tokenservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	beforeOpenStoreRoot = func() {}
	closeStoreRoot      = func(root *os.Root) error { return root.Close() }
)

type storeRoot struct {
	path      string
	root      *os.Root
	closeOnce sync.Once
	closeErr  error
}

func openStoreRoot(path string) (*storeRoot, error) {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect store root: %w", err)
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, fmt.Errorf("create store root: %w", err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect created store root: %w", err)
		}
	}
	if err := validateStoreRoot(info); err != nil {
		return nil, err
	}

	beforeOpenStoreRoot()
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open store root: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil {
		closeErr := root.Close()
		return nil, errors.Join(fmt.Errorf("stat opened store root: %w", err), closeErr)
	}
	if !os.SameFile(info, opened) {
		closeErr := root.Close()
		return nil, errors.Join(fmt.Errorf("store root changed before opening"), closeErr)
	}
	if err := validateStoreRoot(opened); err != nil {
		closeErr := root.Close()
		return nil, errors.Join(err, closeErr)
	}
	if err := root.Chmod(".", 0o700); err != nil {
		closeErr := root.Close()
		return nil, errors.Join(fmt.Errorf("restrict store root: %w", err), closeErr)
	}
	return &storeRoot{path: path, root: root}, nil
}

func (r *storeRoot) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if err := closeStoreRoot(r.root); err != nil {
			r.closeErr = fmt.Errorf("close store root: %w", err)
		}
	})
	return r.closeErr
}

func (r *storeRoot) ReadDir() ([]os.DirEntry, error) {
	directory, err := r.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open store root: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil {
		return nil, errors.Join(fmt.Errorf("read store root: %w", readErr), wrapStoreDirectoryCloseError(closeErr))
	}
	if closeErr != nil {
		return nil, wrapStoreDirectoryCloseError(closeErr)
	}
	return entries, nil
}

func wrapStoreDirectoryCloseError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("close store root directory: %w", err)
}

func (r *storeRoot) ReadRecord(name string) ([]byte, error) {
	name, err := safeStoreBasename(name)
	if err != nil {
		return nil, err
	}
	info, err := r.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("store record must be a regular file")
	}
	return r.root.ReadFile(name)
}

func safeStoreBasename(name string) (string, error) {
	if name == "" || name == "." || filepath.Base(name) != name || !filepath.IsLocal(name) || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("store record name must be a safe basename")
	}
	return name, nil
}

func validateStoreRoot(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("store root must not be a symlink")
	}
	if !info.IsDir() {
		return fmt.Errorf("store root must be a directory")
	}
	return validateStoreRootOwner(info)
}
