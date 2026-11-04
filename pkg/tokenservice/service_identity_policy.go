// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const ServiceIdentityPolicyVersion = 1

var (
	ErrServiceIdentityPolicyNotFound = errors.New("service identity policy not found")
	ErrServiceIdentityPolicyExpired  = errors.New("service identity policy expired")
	ErrServiceIdentityPolicyRevoked  = errors.New("service identity policy revoked")
	ErrServiceIdentityPolicyInvalid  = errors.New("service identity policy invalid")
	ErrServiceIdentityPolicyExists   = errors.New("service identity policy already exists")
)

// ServiceIdentityPolicy authorizes one mTLS certificate subject independently of bootstrap tokens.
type ServiceIdentityPolicy struct {
	Version    int           `json:"version"`
	Revision   uint64        `json:"revision"`
	ID         string        `json:"id"`
	Subject    string        `json:"subject"`
	Audience   string        `json:"audience"`
	Scopes     []string      `json:"scopes"`
	RefreshTTL time.Duration `json:"refresh_ttl"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	RevokedAt  *time.Time    `json:"revoked_at,omitempty"`
}

// ServiceIdentityPolicyStore persists per-subject mTLS authorization policies.
type ServiceIdentityPolicyStore struct {
	storePath string
	root      *storeRoot
	mu        sync.Mutex
}

// NewServiceIdentityPolicyStore creates an authoritative policy store at storePath.
func NewServiceIdentityPolicyStore(storePath string) (*ServiceIdentityPolicyStore, error) {
	storePath = strings.TrimSpace(storePath)
	if storePath == "" {
		return nil, fmt.Errorf("%w: store path is required", ErrServiceIdentityPolicyInvalid)
	}
	root, err := openStoreRoot(storePath)
	if err != nil {
		return nil, fmt.Errorf("prepare service identity policy store directory: %w", err)
	}
	return &ServiceIdentityPolicyStore{storePath: storePath, root: root}, nil
}

// Create persists a new policy and rejects an existing subject policy.
func (s *ServiceIdentityPolicyStore) Create(policy *ServiceIdentityPolicy) error {
	candidate, err := s.preparePolicyWrite(policy)
	if err != nil {
		return err
	}
	return s.withStoreLock(func() error {
		if _, err := s.load(candidate.Subject); err == nil {
			return ErrServiceIdentityPolicyExists
		} else if !errors.Is(err, ErrServiceIdentityPolicyNotFound) {
			return err
		}
		committed, err := createAtomicJSON(s.root, s.policyFileName(candidate.Subject), candidate)
		return serviceIdentityWriteResult("create", committed, err)
	})
}

// Close releases the pinned directory descriptor.
func (s *ServiceIdentityPolicyStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return nil
	}
	return s.root.Close()
}

// Save atomically replaces the policy for its normalized subject.
func (s *ServiceIdentityPolicyStore) Save(policy *ServiceIdentityPolicy) error {
	candidate, err := s.preparePolicyWrite(policy)
	if err != nil {
		return err
	}
	return s.withStoreLock(func() error {
		current, err := s.load(candidate.Subject)
		if err != nil && !errors.Is(err, ErrServiceIdentityPolicyNotFound) {
			return err
		}
		if current == nil {
			candidate.Revision = 1
		} else {
			candidate.Revision = current.Revision + 1
		}
		return s.saveLocked(candidate)
	})
}

func (s *ServiceIdentityPolicyStore) preparePolicyWrite(policy *ServiceIdentityPolicy) (*ServiceIdentityPolicy, error) {
	candidate := cloneServiceIdentityPolicy(policy)
	if candidate == nil {
		return nil, s.validate(candidate)
	}
	candidate.Revision = 1
	if err := s.validate(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

// GetActive returns the current active policy from disk for subject at now.
func (s *ServiceIdentityPolicyStore) GetActive(subject string, now time.Time) (*ServiceIdentityPolicy, error) {
	var policy *ServiceIdentityPolicy
	err := s.withStoreLock(func() error {
		var loadErr error
		policy, loadErr = s.load(subject)
		if loadErr != nil {
			return loadErr
		}
		if policy.RevokedAt != nil {
			return ErrServiceIdentityPolicyRevoked
		}
		if !now.Before(policy.ExpiresAt) {
			return ErrServiceIdentityPolicyExpired
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cloneServiceIdentityPolicy(policy), nil
}

// Revoke marks a policy revoked immediately and persists the change atomically.
func (s *ServiceIdentityPolicyStore) Revoke(subject string, now time.Time) error {
	return s.withStoreLock(func() error {
		policy, err := s.load(subject)
		if err != nil {
			return err
		}
		if policy.RevokedAt == nil {
			revokedAt := now.UTC()
			policy.RevokedAt = &revokedAt
		}
		return s.saveLocked(policy)
	})
}
