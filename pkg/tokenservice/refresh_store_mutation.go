package tokenservice

import (
	"errors"
	"fmt"
)

func (s *RefreshTokenStore) SaveFamily(family *RefreshTokenFamily) (retErr error) {
	candidate := cloneRefreshFamily(family)
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.storePath)
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
	if err := validateRefreshFamily(candidate); err != nil {
		return err
	}
	if s.families[candidate.FamilyID] != nil {
		return ErrRefreshTokenFamilyExists
	}
	if s.hashOwner(candidate.CurrentTokenHash, candidate.FamilyID) != "" || s.consumedHashOwner(candidate, candidate.FamilyID) != "" {
		return fmt.Errorf("refresh token hash already belongs to another family")
	}
	committed, err := s.persist(candidate)
	if committed {
		s.families[candidate.FamilyID] = candidate
	}
	return err
}

func (s *RefreshTokenStore) UpdateFamily(family *RefreshTokenFamily) (retErr error) {
	if family == nil {
		return fmt.Errorf("refresh token family is required")
	}
	candidate := cloneRefreshFamily(family)
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := lockStore(s.storePath)
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
	previous := s.families[candidate.FamilyID]
	if previous != nil && previous.CurrentTokenHash != candidate.CurrentTokenHash && !containsHash(candidate.ConsumedGenerationHashes, previous.CurrentTokenHash) {
		candidate.ConsumedGenerationHashes = append(candidate.ConsumedGenerationHashes, previous.CurrentTokenHash)
	}
	if err := validateRefreshFamily(candidate); err != nil {
		return err
	}
	if s.hashOwner(candidate.CurrentTokenHash, candidate.FamilyID) != "" || s.consumedHashOwner(candidate, candidate.FamilyID) != "" {
		return fmt.Errorf("refresh token hash already belongs to another family")
	}
	committed, err := s.persist(candidate)
	if committed {
		s.families[candidate.FamilyID] = candidate
	}
	return err
}
