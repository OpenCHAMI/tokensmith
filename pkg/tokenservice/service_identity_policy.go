// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	mu        sync.Mutex
}

// NewServiceIdentityPolicyStore creates an authoritative policy store at storePath.
func NewServiceIdentityPolicyStore(storePath string) (*ServiceIdentityPolicyStore, error) {
	storePath = strings.TrimSpace(storePath)
	if storePath == "" {
		return nil, fmt.Errorf("%w: store path is required", ErrServiceIdentityPolicyInvalid)
	}
	if err := os.MkdirAll(storePath, 0o700); err != nil {
		return nil, fmt.Errorf("create service identity policy store: %w", err)
	}
	return &ServiceIdentityPolicyStore{storePath: storePath}, nil
}

// Create persists a new policy and rejects an existing subject policy.
func (s *ServiceIdentityPolicyStore) Create(policy *ServiceIdentityPolicy) error {
	candidate := cloneServiceIdentityPolicy(policy)
	if err := s.validate(candidate); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	committed, err := createAtomicJSON(s.policyPath(candidate.Subject), candidate)
	return serviceIdentityWriteResult("create", committed, err)
}

// Save atomically replaces the policy for its normalized subject.
func (s *ServiceIdentityPolicyStore) Save(policy *ServiceIdentityPolicy) error {
	candidate := cloneServiceIdentityPolicy(policy)
	if err := s.validate(candidate); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(candidate)
}

// GetActive returns the current active policy from disk for subject at now.
func (s *ServiceIdentityPolicyStore) GetActive(subject string, now time.Time) (*ServiceIdentityPolicy, error) {
	policy, err := s.load(subject)
	if err != nil {
		return nil, err
	}
	if policy.RevokedAt != nil {
		return nil, ErrServiceIdentityPolicyRevoked
	}
	if !now.Before(policy.ExpiresAt) {
		return nil, ErrServiceIdentityPolicyExpired
	}
	return cloneServiceIdentityPolicy(policy), nil
}

// Revoke marks a policy revoked immediately and persists the change atomically.
func (s *ServiceIdentityPolicyStore) Revoke(subject string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	policy, err := s.load(subject)
	if err != nil {
		return err
	}
	if policy.RevokedAt == nil {
		revokedAt := now.UTC()
		policy.RevokedAt = &revokedAt
	}
	return s.saveLocked(policy)
}

// List returns defensive copies of every valid policy currently on disk.
func (s *ServiceIdentityPolicyStore) List() ([]ServiceIdentityPolicy, error) {
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		return nil, fmt.Errorf("read service identity policy store: %w", err)
	}
	policies := make([]ServiceIdentityPolicy, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.storePath, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("%w: read policy file", ErrServiceIdentityPolicyInvalid)
		}
		var policy ServiceIdentityPolicy
		if err := json.Unmarshal(data, &policy); err != nil {
			return nil, fmt.Errorf("%w: decode policy file", ErrServiceIdentityPolicyInvalid)
		}
		if err := s.validate(&policy); err != nil || entry.Name() != filepath.Base(s.policyPath(policy.Subject)) {
			return nil, fmt.Errorf("%w: invalid policy file", ErrServiceIdentityPolicyInvalid)
		}
		policies = append(policies, *cloneServiceIdentityPolicy(&policy))
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].Subject < policies[j].Subject })
	return policies, nil
}

func (s *ServiceIdentityPolicyStore) load(subject string) (*ServiceIdentityPolicy, error) {
	subject = normalizeServiceIdentitySubject(subject)
	if subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrServiceIdentityPolicyInvalid)
	}
	data, err := os.ReadFile(s.policyPath(subject))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrServiceIdentityPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read policy file", ErrServiceIdentityPolicyInvalid)
	}
	var policy ServiceIdentityPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("%w: decode policy file", ErrServiceIdentityPolicyInvalid)
	}
	if err := s.validate(&policy); err != nil || policy.Subject != subject {
		return nil, fmt.Errorf("%w: malformed policy", ErrServiceIdentityPolicyInvalid)
	}
	entries, err := os.ReadDir(s.storePath)
	if err != nil {
		return nil, fmt.Errorf("%w: read policy store", ErrServiceIdentityPolicyInvalid)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == filepath.Base(s.policyPath(subject)) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.storePath, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("%w: read policy file", ErrServiceIdentityPolicyInvalid)
		}
		var candidate ServiceIdentityPolicy
		if err := json.Unmarshal(data, &candidate); err != nil {
			return nil, fmt.Errorf("%w: decode policy file", ErrServiceIdentityPolicyInvalid)
		}
		if normalizeServiceIdentitySubject(candidate.Subject) == subject {
			return nil, fmt.Errorf("%w: duplicate subject", ErrServiceIdentityPolicyInvalid)
		}
	}
	return &policy, nil
}

func (s *ServiceIdentityPolicyStore) saveLocked(policy *ServiceIdentityPolicy) error {
	copy := cloneServiceIdentityPolicy(policy)
	committed, err := atomicJSONWrite(s.policyPath(copy.Subject), copy)
	return serviceIdentityWriteResult("write", committed, err)
}

func serviceIdentityWriteResult(operation string, committed bool, err error) error {
	if err == nil {
		return nil
	}
	if committed {
		return fmt.Errorf("%s service identity policy committed but directory durability failed: %w", operation, err)
	}
	return fmt.Errorf("%s service identity policy: %w", operation, err)
}

func (s *ServiceIdentityPolicyStore) policyPath(subject string) string {
	sum := sha256.Sum256([]byte(normalizeServiceIdentitySubject(subject)))
	return filepath.Join(s.storePath, hex.EncodeToString(sum[:])+".json")
}

func (s *ServiceIdentityPolicyStore) validate(policy *ServiceIdentityPolicy) error {
	if policy == nil || policy.Version != ServiceIdentityPolicyVersion || strings.TrimSpace(policy.ID) == "" {
		return ErrServiceIdentityPolicyInvalid
	}
	policy.Subject = normalizeServiceIdentitySubject(policy.Subject)
	policy.Audience = strings.TrimSpace(policy.Audience)
	if policy.Subject == "" || policy.Audience == "" || policy.CreatedAt.IsZero() || policy.ExpiresAt.IsZero() || !policy.ExpiresAt.After(policy.CreatedAt) || policy.RefreshTTL <= 0 || policy.RefreshTTL > policy.ExpiresAt.Sub(policy.CreatedAt) {
		return ErrServiceIdentityPolicyInvalid
	}
	if len(policy.Scopes) == 0 {
		return ErrServiceIdentityPolicyInvalid
	}
	for index, scope := range policy.Scopes {
		policy.Scopes[index] = strings.TrimSpace(scope)
		if policy.Scopes[index] == "" {
			return ErrServiceIdentityPolicyInvalid
		}
	}
	return nil
}

func normalizeServiceIdentitySubject(subject string) string {
	return strings.TrimSpace(subject)
}

func cloneServiceIdentityPolicy(policy *ServiceIdentityPolicy) *ServiceIdentityPolicy {
	if policy == nil {
		return nil
	}
	copy := *policy
	copy.Scopes = append([]string(nil), policy.Scopes...)
	if policy.RevokedAt != nil {
		revokedAt := *policy.RevokedAt
		copy.RevokedAt = &revokedAt
	}
	return &copy
}
