package tokenservice

import (
	"errors"
	"fmt"
	"os"
	"time"
)

func (s *BootstrapTokenStore) CleanupExpired() (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.root)
	if err != nil {
		return err
	}
	defer func() {
		if err := unlockStore(lock); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	s.policies = make(map[string]*BootstrapTokenPolicy)
	if err := s.load(); err != nil {
		return err
	}
	now := time.Now()
	for hash, policy := range s.policies {
		if now.Before(policy.ExpiresAt) {
			continue
		}
		removed, err := removeStoreFile(s.root, hash)
		if removed {
			delete(s.policies, hash)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *RefreshTokenStore) CleanupExpired() (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.root)
	if err != nil {
		return err
	}
	defer func() {
		if err := unlockStore(lock); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	s.families = make(map[string]*RefreshTokenFamily)
	if err := s.load(); err != nil {
		return err
	}
	now := time.Now()
	for id, family := range s.families {
		if now.Before(family.ExpiresAt) {
			continue
		}
		removed, err := removeStoreFile(s.root, id)
		if removed {
			delete(s.families, id)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func removeStoreFile(root *storeRoot, id string) (bool, error) {
	name, err := safeStoreBasename(id + ".json")
	if err != nil {
		return false, err
	}
	if err := root.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove expired store file: %w", err)
	}
	if err := syncAndCloseDirectory(openStoreDirectory, root, "store"); err != nil {
		return true, &CommittedWriteError{Err: err}
	}
	return true, nil
}
