// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrServiceIdentityPolicyBindingInvalid = errors.New("service identity policy binding invalid")
	ErrServiceIdentityPolicyReplaced       = errors.New("service identity policy replaced")
)

type serviceIdentityPolicyInstance struct {
	Version    int           `json:"version"`
	Revision   uint64        `json:"revision"`
	ID         string        `json:"id"`
	Subject    string        `json:"subject"`
	Audience   string        `json:"audience"`
	Scopes     []string      `json:"scopes"`
	RefreshTTL time.Duration `json:"refresh_ttl"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
}

func newServiceIdentityPolicyBinding(policy *ServiceIdentityPolicy) (*ServiceIdentityPolicyBinding, error) {
	fingerprint, err := serviceIdentityPolicyFingerprint(policy)
	if err != nil {
		return nil, err
	}
	return &ServiceIdentityPolicyBinding{
		Subject:     policy.Subject,
		PolicyID:    policy.ID,
		Revision:    policy.Revision,
		Fingerprint: fingerprint,
	}, nil
}

func serviceIdentityPolicyFingerprint(policy *ServiceIdentityPolicy) (string, error) {
	instance := serviceIdentityPolicyInstance{
		Version:    policy.Version,
		Revision:   policy.Revision,
		ID:         policy.ID,
		Subject:    policy.Subject,
		Audience:   policy.Audience,
		Scopes:     policy.Scopes,
		RefreshTTL: policy.RefreshTTL,
		CreatedAt:  policy.CreatedAt,
		ExpiresAt:  policy.ExpiresAt,
	}
	data, err := json.Marshal(instance)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func validateServiceIdentityPolicyBinding(binding *ServiceIdentityPolicyBinding) error {
	if binding == nil || strings.TrimSpace(binding.Subject) == "" || strings.TrimSpace(binding.PolicyID) == "" || binding.Revision == 0 {
		return ErrServiceIdentityPolicyBindingInvalid
	}
	fingerprint, err := hex.DecodeString(binding.Fingerprint)
	if err != nil || len(fingerprint) != sha256.Size {
		return ErrServiceIdentityPolicyBindingInvalid
	}
	return nil
}

func (s *ServiceIdentityPolicyStore) ValidateRefreshBinding(binding *ServiceIdentityPolicyBinding, now time.Time) error {
	if err := validateServiceIdentityPolicyBinding(binding); err != nil {
		return err
	}
	policy, err := s.GetActive(binding.Subject, now)
	if err != nil {
		return err
	}
	fingerprint, err := serviceIdentityPolicyFingerprint(policy)
	if err != nil {
		return err
	}
	if policy.ID != binding.PolicyID || policy.Revision != binding.Revision || fingerprint != binding.Fingerprint {
		return ErrServiceIdentityPolicyReplaced
	}
	return nil
}
