// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package v1

import (
	"fmt"
	"time"

	"github.com/openchami/fabrica/pkg/resource"
	"github.com/openchami/tokensmith/pkg/tokenservice"
)

// Adapter functions for bidirectional conversion between legacy models and Fabrica resources.
// These enable a zero-downtime migration strategy with dual-write capability.

// BootstrapTokenPolicyToResource converts a legacy BootstrapTokenPolicy to a Fabrica resource.
//
// This adapter separates immutable policy (Spec) from mutable state (Status), enabling
// Fabrica's storage backend to enforce RFC 8693 Section 6 immutability constraints.
//
// Usage during migration:
//   - Phase 1: Write to both legacy storage and Fabrica storage
//   - Phase 2: Read from Fabrica storage, fall back to legacy
//   - Phase 3: Remove legacy storage
func BootstrapTokenPolicyToResource(legacy *tokenservice.BootstrapTokenPolicy) (*BootstrapTokenPolicy, error) {
	if legacy == nil {
		return nil, fmt.Errorf("nil BootstrapTokenPolicy")
	}

	// Generate metadata
	metadata := resource.Metadata{
		Name:      legacy.ID, // Use legacy ID as Fabrica resource name
		CreatedAt: legacy.CreatedAt,
		UpdatedAt: legacy.CreatedAt, // Initially same as created
	}

	// Populate immutable Spec (policy)
	spec := BootstrapTokenPolicySpec{
		Subject:           legacy.Subject,
		Audience:          legacy.Audience,
		Scopes:            legacy.Scopes,
		TTL:               int64(legacy.TTL), // Convert time.Duration to int64 (nanoseconds)
		RefreshTTL:        int64(legacy.RefreshTTL),
		TokenHash:         legacy.TokenHash,
		ExpiresAt:         legacy.ExpiresAt,
		BindingIdentifier: legacy.BindingIdentifier,
	}

	// Populate mutable Status (state)
	status := BootstrapTokenPolicyStatus{
		ConsumedAt:           legacy.ConsumedAt,
		ConsumedByIP:         legacy.ConsumedByIP,
		ReplayAttempts:       legacy.ReplayAttempts,
		IssuedAccessTokenID:  legacy.IssuedAccessTokenID,
		IssuedRefreshTokenID: legacy.IssuedRefreshTokenID,
	}

	return &BootstrapTokenPolicy{
		APIVersion: "tokensmith.openchami.org/v1",
		Kind:       "BootstrapTokenPolicy",
		Metadata:   metadata,
		Spec:       spec,
		Status:     status,
	}, nil
}

// BootstrapTokenPolicyFromResource converts a Fabrica resource back to legacy BootstrapTokenPolicy.
//
// This adapter reconstructs the legacy flat model from Fabrica's Spec/Status separation.
//
// Usage during migration:
//   - Enables legacy code to read from Fabrica storage
//   - Zero API changes (legacy HTTP handlers still work)
func BootstrapTokenPolicyFromResource(resource *BootstrapTokenPolicy) (*tokenservice.BootstrapTokenPolicy, error) {
	if resource == nil {
		return nil, fmt.Errorf("nil BootstrapTokenPolicyResource")
	}

	// Reconstruct legacy model
	legacy := &tokenservice.BootstrapTokenPolicy{
		ID:                   resource.Metadata.Name, // Fabrica name = legacy ID
		Subject:              resource.Spec.Subject,
		Audience:             resource.Spec.Audience,
		Scopes:               resource.Spec.Scopes,
		TTL:                  time.Duration(resource.Spec.TTL), // Convert int64 nanoseconds to time.Duration
		RefreshTTL:           time.Duration(resource.Spec.RefreshTTL),
		TokenHash:            resource.Spec.TokenHash,
		CreatedAt:            resource.Metadata.CreatedAt,
		ExpiresAt:            resource.Spec.ExpiresAt,
		ConsumedAt:           resource.Status.ConsumedAt,
		ConsumedByIP:         resource.Status.ConsumedByIP,
		ReplayAttempts:       resource.Status.ReplayAttempts,
		BindingIdentifier:    resource.Spec.BindingIdentifier,
		IssuedAccessTokenID:  resource.Status.IssuedAccessTokenID,
		IssuedRefreshTokenID: resource.Status.IssuedRefreshTokenID,
	}

	return legacy, nil
}

// RefreshTokenFamilyToResource converts a legacy RefreshTokenFamily to a Fabrica resource.
//
// This adapter separates immutable original grant (Spec) from mutable rotation state (Status),
// enabling NIST SP 800-63-4 Section 6.2.3 compliance enforcement.
//
// Key transformation:
//   - CurrentTokenHash moves to Spec (security-critical for O(1) validation)
//   - Rotation history and replay detection live in Status
func RefreshTokenFamilyToResource(legacy *tokenservice.RefreshTokenFamily) (*RefreshTokenFamily, error) {
	if legacy == nil {
		return nil, fmt.Errorf("nil RefreshTokenFamily")
	}

	// Generate metadata
	metadata := resource.Metadata{
		Name:      legacy.FamilyID, // FamilyID is stable identifier
		CreatedAt: legacy.IssuedAt,
		UpdatedAt: legacy.IssuedAt, // Initially same as issued
	}

	// Populate immutable Spec (original grant)
	spec := RefreshTokenFamilySpec{
		FamilyID:          legacy.FamilyID,
		CurrentTokenHash:  legacy.CurrentTokenHash, // Security-critical: enables O(1) validation
		Subject:           legacy.Subject,
		Audience:          legacy.Audience,
		Scopes:            legacy.Scopes,
		IssuedAt:          legacy.IssuedAt,
		ExpiresAt:         legacy.ExpiresAt,
		BindingIdentifier: legacy.BindingIdentifier,
	}

	// Populate mutable Status (rotation state)
	status := RefreshTokenFamilyStatus{
		LastUsedAt:       legacy.LastUsedAt,
		UsageCount:       legacy.UsageCount,
		ReplayDetectedAt: legacy.ReplayDetectedAt,
		RevokedAt:        legacy.RevokedAt,
	}

	return &RefreshTokenFamily{
		APIVersion: "tokensmith.openchami.org/v1",
		Kind:       "RefreshTokenFamily",
		Metadata:   metadata,
		Spec:       spec,
		Status:     status,
	}, nil
}

// RefreshTokenFamilyFromResource converts a Fabrica resource back to legacy RefreshTokenFamily.
//
// This adapter reconstructs the legacy flat model from Fabrica's Spec/Status separation.
//
// Usage during migration:
//   - Enables legacy code to read from Fabrica storage
//   - Zero API changes (legacy HTTP handlers still work)
func RefreshTokenFamilyFromResource(resource *RefreshTokenFamily) (*tokenservice.RefreshTokenFamily, error) {
	if resource == nil {
		return nil, fmt.Errorf("nil RefreshTokenFamilyResource")
	}

	// Reconstruct legacy model
	legacy := &tokenservice.RefreshTokenFamily{
		FamilyID:          resource.Spec.FamilyID,
		CurrentTokenHash:  resource.Spec.CurrentTokenHash,
		Subject:           resource.Spec.Subject,
		Audience:          resource.Spec.Audience,
		Scopes:            resource.Spec.Scopes,
		IssuedAt:          resource.Spec.IssuedAt,
		ExpiresAt:         resource.Spec.ExpiresAt,
		LastUsedAt:        resource.Status.LastUsedAt,
		UsageCount:        resource.Status.UsageCount,
		ReplayDetectedAt:  resource.Status.ReplayDetectedAt,
		RevokedAt:         resource.Status.RevokedAt,
		BindingIdentifier: resource.Spec.BindingIdentifier,
	}

	return legacy, nil
}
