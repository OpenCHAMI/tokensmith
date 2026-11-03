//go:build darwin || linux

package tokenservice

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var beforeStoreFlock = func() {}

func lockStore(root *storeRoot) (*os.File, error) {
	file, err := root.root.OpenFile(".store.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		created, createErr := root.root.OpenFile(".store.lock", os.O_CREATE|os.O_EXCL|os.O_RDWR|unix.O_CLOEXEC, 0o600)
		if createErr != nil && !errors.Is(createErr, os.ErrExist) {
			return nil, fmt.Errorf("create store lock: %w", createErr)
		}
		if createErr == nil {
			if closeErr := created.Close(); closeErr != nil {
				return nil, fmt.Errorf("close created store lock: %w", closeErr)
			}
		}
		file, err = root.root.OpenFile(".store.lock", os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open store lock: %w", err)
	}
	beforeStoreFlock()
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
