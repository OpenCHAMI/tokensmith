package tokenservice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (s *BootstrapTokenStore) CleanupExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, policy := range s.policies {
		if time.Now().Before(policy.ExpiresAt) {
			continue
		}
		if err := removeStoreFile(s.storePath, hash); err != nil {
			return err
		}
		delete(s.policies, hash)
	}
	return nil
}

func (s *RefreshTokenStore) CleanupExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, family := range s.families {
		if time.Now().Before(family.ExpiresAt) {
			continue
		}
		if err := removeStoreFile(s.storePath, id); err != nil {
			return err
		}
		delete(s.families, id)
	}
	return nil
}

func removeStoreFile(directory, id string) error {
	if err := os.Remove(filepath.Join(directory, id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove expired store file: %w", err)
	}
	return syncAndCloseDirectory(openStoreDirectory, directory, "store")
}
