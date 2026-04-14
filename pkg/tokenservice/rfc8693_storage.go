// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// BootstrapTokenStore manages storage and retrieval of opaque bootstrap token policies.
// Bootstrap tokens are single-use, server-side validated tokens.
// See: RFC 8693 Section 3 (Token Request)
type BootstrapTokenStore struct {
	storePath string
	mu        sync.RWMutex
	policies  map[string]*BootstrapTokenPolicy // Map of token hash -> policy
}

// RefreshTokenStore manages storage and retrieval of refresh token families.
// Refresh token families are tracked for replay detection.
// See: NIST SP 800-63-4 Section 6.2.3 (Token Rotation and Replay Detection)
type RefreshTokenStore struct {
	storePath string
	mu        sync.RWMutex
	families  map[string]*RefreshTokenFamily // Map of family ID -> family
}

// NewBootstrapTokenStore creates a new bootstrap token store.
func NewBootstrapTokenStore(storePath string) (*BootstrapTokenStore, error) {
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create bootstrap token store directory: %w", err)
	}

	store := &BootstrapTokenStore{
		storePath: storePath,
		policies:  make(map[string]*BootstrapTokenPolicy),
	}

	// Load existing policies from disk
	if err := store.load(); err != nil {
		log.Warn().
			Err(err).
			Str("store", "bootstrap_token").
			Msg("Failed to load bootstrap token policies from disk; starting fresh")
		// Don't fail on load error; start with empty store
	}

	return store, nil
}

// NewRefreshTokenStore creates a new refresh token store.
func NewRefreshTokenStore(storePath string) (*RefreshTokenStore, error) {
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create refresh token store directory: %w", err)
	}

	store := &RefreshTokenStore{
		storePath: storePath,
		families:  make(map[string]*RefreshTokenFamily),
	}

	// Load existing families from disk
	if err := store.load(); err != nil {
		log.Warn().
			Err(err).
			Str("store", "refresh_token").
			Msg("Failed to load refresh token families from disk; starting fresh")
	}

	return store, nil
}

// SavePolicy stores a bootstrap token policy.
// Policies are indexed by token hash for O(1) lookup during validation.
func (s *BootstrapTokenStore) SavePolicy(policy *BootstrapTokenPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policies[policy.TokenHash] = policy

	// Persist to disk
	filePath := filepath.Join(s.storePath, policy.TokenHash+".json")
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal bootstrap policy: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write bootstrap policy to disk: %w", err)
	}

	log.Debug().
		Str("token_hash_prefix", policy.TokenHash[:8]).
		Str("subject", policy.Subject).
		Str("audience", policy.Audience).
		Msg("Bootstrap token policy saved")

	return nil
}

// GetPolicy retrieves a bootstrap token policy by token hash.
func (s *BootstrapTokenStore) GetPolicy(tokenHash string) (*BootstrapTokenPolicy, error) {
	s.mu.RLock()
	policy, ok := s.policies[tokenHash]
	s.mu.RUnlock()
	if ok {
		return policy, nil
	}

	// Fallback: load directly from disk for policies created after store startup.
	policy, err := s.loadPolicyFromDisk(tokenHash)
	if err != nil {
		return nil, err
	}

	// Promote loaded policy to memory cache for subsequent O(1) lookups.
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, exists := s.policies[tokenHash]; exists {
		return existing, nil
	}
	s.policies[tokenHash] = policy

	return policy, nil
}

// loadPolicyFromDisk reads and validates a single bootstrap policy file by token hash.
func (s *BootstrapTokenStore) loadPolicyFromDisk(tokenHash string) (*BootstrapTokenPolicy, error) {
	filePath := filepath.Join(s.storePath, tokenHash+".json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("bootstrap token policy not found")
		}
		return nil, fmt.Errorf("failed to read bootstrap policy file: %w", err)
	}

	var policy BootstrapTokenPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bootstrap policy file: %w", err)
	}

	if policy.TokenHash != tokenHash {
		return nil, fmt.Errorf("bootstrap token hash mismatch: expected %s, got %s", tokenHash, policy.TokenHash)
	}

	return &policy, nil
}

// UpdatePolicy updates a bootstrap token policy (e.g., mark as consumed).
// This is atomic per token hash.
func (s *BootstrapTokenStore) UpdatePolicy(policy *BootstrapTokenPolicy) error {
	return s.SavePolicy(policy)
}

// SaveFamily stores a refresh token family.
func (s *RefreshTokenStore) SaveFamily(family *RefreshTokenFamily) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.families[family.FamilyID] = family

	// Persist to disk
	filePath := filepath.Join(s.storePath, family.FamilyID+".json")
	data, err := json.MarshalIndent(family, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token family: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write refresh token family to disk: %w", err)
	}

	log.Debug().
		Str("family_id", family.FamilyID).
		Str("subject", family.Subject).
		Str("audience", family.Audience).
		Int("usage_count", family.UsageCount).
		Msg("Refresh token family saved")

	return nil
}

// GetFamily retrieves a refresh token family by family ID.
func (s *RefreshTokenStore) GetFamily(familyID string) (*RefreshTokenFamily, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	family, ok := s.families[familyID]
	if !ok {
		return nil, fmt.Errorf("refresh token family not found")
	}

	return family, nil
}

// GetFamilyByTokenHash retrieves a refresh token family by current token hash.
// Used for opaque refresh token lookup (family ID is not embedded in the token).
// Per NIST SP 800-63-4 Section 6.2.3, family tracking enables replay detection.
func (s *RefreshTokenStore) GetFamilyByTokenHash(tokenHash string) (*RefreshTokenFamily, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, family := range s.families {
		if family.CurrentTokenHash == tokenHash {
			return family, nil
		}
	}

	return nil, fmt.Errorf("refresh token family not found for token hash")
}

// UpdateFamily updates a refresh token family (e.g., rotate token, track usage).
func (s *RefreshTokenStore) UpdateFamily(family *RefreshTokenFamily) error {
	return s.SaveFamily(family)
}

// load loads all stored policies/families from disk.
func (s *BootstrapTokenStore) load() error {
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist yet; start fresh
		}
		return fmt.Errorf("failed to read bootstrap token store directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(s.storePath, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Warn().Err(err).Str("file", entry.Name()).Msg("Failed to read bootstrap policy file")
			continue
		}

		var policy BootstrapTokenPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			log.Warn().Err(err).Str("file", entry.Name()).Msg("Failed to unmarshal bootstrap policy")
			continue
		}

		s.policies[policy.TokenHash] = &policy
	}

	return nil
}

// load loads all stored families from disk.
func (s *RefreshTokenStore) load() error {
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read refresh token store directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		filePath := filepath.Join(s.storePath, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			log.Warn().Err(err).Str("file", entry.Name()).Msg("Failed to read refresh token family file")
			continue
		}

		var family RefreshTokenFamily
		if err := json.Unmarshal(data, &family); err != nil {
			log.Warn().Err(err).Str("file", entry.Name()).Msg("Failed to unmarshal refresh token family")
			continue
		}

		s.families[family.FamilyID] = &family
	}

	return nil
}

// CleanupExpired removes expired bootstrap policies and refresh families.
// This should be run periodically to prevent unbounded growth.
func (s *BootstrapTokenStore) CleanupExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expired := make([]string, 0)

	for hash, policy := range s.policies {
		if now.After(policy.ExpiresAt) {
			expired = append(expired, hash)
		}
	}

	for _, hash := range expired {
		delete(s.policies, hash)
		filePath := filepath.Join(s.storePath, hash+".json")
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn().
				Err(err).
				Str("file_path", filePath).
				Str("token_hash_prefix", hash[:8]).
				Msg("Failed to remove expired bootstrap policy file")
		}
		log.Debug().Str("token_hash_prefix", hash[:8]).Msg("Cleaned up expired bootstrap policy")
	}

	return nil
}

// CleanupExpired removes expired refresh token families.
func (s *RefreshTokenStore) CleanupExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expired := make([]string, 0)

	for familyID, family := range s.families {
		if now.After(family.ExpiresAt) {
			expired = append(expired, familyID)
		}
	}

	for _, familyID := range expired {
		delete(s.families, familyID)
		filePath := filepath.Join(s.storePath, familyID+".json")
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Warn().
				Err(err).
				Str("file_path", filePath).
				Str("family_id", familyID).
				Msg("Failed to remove expired refresh token family file")
		}
		log.Debug().Str("family_id", familyID).Msg("Cleaned up expired refresh token family")
	}

	return nil
}
