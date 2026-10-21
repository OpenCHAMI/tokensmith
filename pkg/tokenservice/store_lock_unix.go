//go:build darwin || linux

package tokenservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockStore(directory string) (*os.File, error) {
	file, err := os.OpenFile(filepath.Join(directory, ".store.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open store lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("lock store: %w", err), closeErr)
	}
	return file, nil
}

func unlockStore(file *os.File) error {
	unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
	closeErr := file.Close()
	if unlockErr != nil {
		return fmt.Errorf("unlock store: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close store lock: %w", closeErr)
	}
	return nil
}
