// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"fmt"
	"strings"
	"time"
)

// ProviderMode selects the upstream token validation protocol.
type ProviderMode string

const (
	ProviderModeGeneric ProviderMode = "generic"
	ProviderModeVault   ProviderMode = "vault"
)

const (
	// DefaultVaultUserInfoFallbackTTL bounds UserInfo claims without an expiration by default.
	DefaultVaultUserInfoFallbackTTL = 5 * time.Minute
	// MaximumVaultUserInfoFallbackTTL prevents configuration from turning fallback claims into long-lived credentials.
	MaximumVaultUserInfoFallbackTTL = 15 * time.Minute
)

// ParseProviderMode parses a provider mode at a configuration boundary.
func ParseProviderMode(value string) (ProviderMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(ProviderModeGeneric):
		return ProviderModeGeneric, nil
	case string(ProviderModeVault):
		return ProviderModeVault, nil
	default:
		return "", fmt.Errorf("unsupported OIDC provider mode %q", value)
	}
}

// ValidateVaultUserInfoFallbackTTL enforces a short lifetime for claims without exp.
func ValidateVaultUserInfoFallbackTTL(ttl time.Duration) error {
	if ttl <= 0 || ttl > MaximumVaultUserInfoFallbackTTL {
		return fmt.Errorf("vault UserInfo fallback TTL must be greater than zero and at most %s", MaximumVaultUserInfoFallbackTTL)
	}
	return nil
}

// WithProviderMode selects the upstream provider protocol.
func WithProviderMode(mode ProviderMode) SimpleProviderOption {
	return func(provider *SimpleProvider) {
		provider.mode = mode
	}
}

// WithVaultUserInfoFallbackTTL bounds Vault UserInfo responses that omit exp.
func WithVaultUserInfoFallbackTTL(ttl time.Duration) SimpleProviderOption {
	return func(provider *SimpleProvider) {
		if ValidateVaultUserInfoFallbackTTL(ttl) == nil {
			provider.vaultUserInfoFallbackTTL = ttl
		}
	}
}
