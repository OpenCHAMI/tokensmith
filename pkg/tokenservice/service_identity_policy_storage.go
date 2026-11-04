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
)

// List returns defensive copies of every valid policy currently on disk.
func (s *ServiceIdentityPolicyStore) List() ([]ServiceIdentityPolicy, error) {
	var policies []ServiceIdentityPolicy
	err := s.withStoreLock(func() error {
		entries, err := s.root.ReadDir()
		if err != nil {
			return fmt.Errorf("read service identity policy store: %w", err)
		}
		policies = make([]ServiceIdentityPolicy, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			data, err := s.root.ReadRecord(entry.Name())
			if err != nil {
				return fmt.Errorf("%w: read policy file", ErrServiceIdentityPolicyInvalid)
			}
			var policy ServiceIdentityPolicy
			if err := json.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("%w: decode policy file", ErrServiceIdentityPolicyInvalid)
			}
			if err := s.validate(&policy); err != nil || entry.Name() != s.policyFileName(policy.Subject) {
				return fmt.Errorf("%w: invalid policy file", ErrServiceIdentityPolicyInvalid)
			}
			policies = append(policies, *cloneServiceIdentityPolicy(&policy))
		}
		sort.Slice(policies, func(i, j int) bool { return policies[i].Subject < policies[j].Subject })
		return nil
	})
	return policies, err
}

func (s *ServiceIdentityPolicyStore) load(subject string) (*ServiceIdentityPolicy, error) {
	subject = normalizeServiceIdentitySubject(subject)
	if subject == "" {
		return nil, fmt.Errorf("%w: subject is required", ErrServiceIdentityPolicyInvalid)
	}
	data, err := s.root.ReadRecord(s.policyFileName(subject))
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
	if err := s.validate(&policy); err != nil {
		return nil, fmt.Errorf("malformed service identity policy: %w", err)
	}
	if policy.Subject != subject {
		return nil, fmt.Errorf("%w: malformed policy", ErrServiceIdentityPolicyInvalid)
	}
	entries, err := s.root.ReadDir()
	if err != nil {
		return nil, fmt.Errorf("%w: read policy store", ErrServiceIdentityPolicyInvalid)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" || entry.Name() == s.policyFileName(subject) {
			continue
		}
		data, err := s.root.ReadRecord(entry.Name())
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
	committed, err := atomicJSONWrite(s.root, s.policyFileName(copy.Subject), copy)
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

func (s *ServiceIdentityPolicyStore) policyFileName(subject string) string {
	sum := sha256.Sum256([]byte(normalizeServiceIdentitySubject(subject)))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (s *ServiceIdentityPolicyStore) validate(policy *ServiceIdentityPolicy) error {
	if policy == nil || policy.Version != ServiceIdentityPolicyVersion || strings.TrimSpace(policy.ID) == "" {
		return ErrServiceIdentityPolicyInvalid
	}
	if policy.Revision == 0 {
		return fmt.Errorf("%w: revision is required", ErrServiceIdentityPolicyInvalid)
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
