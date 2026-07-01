// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package v1

import (
	"time"

	"github.com/openchami/fabrica/pkg/resource"
)

// RefreshTokenFamily is a Fabrica resource for refresh token families.
//
// This resource tracks refresh token rotation for replay detection per NIST SP 800-63-4
// Section 6.2.3. Each family represents a chain of rotated refresh tokens from the same
// original grant.
//
// Storage Strategy:
// - Dedicated PostgreSQL table: refresh_token_families
// - O(1) token validation via indexed CurrentTokenHash (fixes O(n) file scan!)
// - Immutable original grant (NIST 800-63-4 compliance)
// - Mutable usage tracking in Status (rotation count, replay detection)
//
// Security:
// - CurrentTokenHash never exposed in API (json:"-")
// - Immutable scopes/audience prevent privilege escalation
// - Unique constraint enforces one valid token per family
//
// +fabrica:resource
// +fabrica:storage=dedicated
// +fabrica:storage:backend=postgres
// +fabrica:storage:table=refresh_token_families
// +fabrica:index:current_token_hash
// +fabrica:index:subject
// +fabrica:index:expires_at
type RefreshTokenFamily struct {
	APIVersion string                   `json:"apiVersion"`
	Kind       string                   `json:"kind"`
	Metadata   resource.Metadata        `json:"metadata"`
	Spec       RefreshTokenFamilySpec   `json:"spec" validate:"required"`
	Status     RefreshTokenFamilyStatus `json:"status,omitempty"`
}

// RefreshTokenFamilySpec defines the immutable original grant for a refresh token family.
// Per NIST SP 800-63-4 Section 6.2.3, the original grant never changes during rotation.
type RefreshTokenFamilySpec struct {
	// FamilyID is the stable identifier shared across all rotations.
	// +fabrica:field:immutable
	FamilyID string `json:"family_id" validate:"required"`

	// CurrentTokenHash is SHA-256(currently-valid-refresh-token).
	// SECURITY: Never expose this field in API responses.
	// This is the ONLY way to validate refresh tokens (O(1) indexed lookup).
	// +fabrica:field:unique
	// +fabrica:field:index
	CurrentTokenHash string `json:"-"`

	// Subject identifies the service (e.g., "boot-service", "magellan")
	// +fabrica:field:immutable
	// +fabrica:field:index
	Subject string `json:"subject" validate:"required"`

	// Audience identifies the target service (e.g., "hsm", "smd", "inventory")
	// +fabrica:field:immutable
	Audience string `json:"audience" validate:"required"`

	// Scopes are the original pre-authorized scopes (immutable per NIST 800-63-4).
	// +fabrica:field:immutable
	Scopes []string `json:"scopes" validate:"required,min=1"`

	// IssuedAt is when the original refresh token was first issued.
	// +fabrica:field:immutable
	IssuedAt time.Time `json:"issued_at" validate:"required"`

	// ExpiresAt is when this entire family expires (all rotations invalid).
	// +fabrica:field:immutable
	// +fabrica:field:index
	ExpiresAt time.Time `json:"expires_at" validate:"required"`

	// BindingIdentifier is optional metadata for audit (e.g., pod/instance ID)
	BindingIdentifier string `json:"binding_identifier,omitempty"`
}

// RefreshTokenFamilyStatus tracks the mutable state of a refresh token family.
// This includes rotation history, usage tracking, and security events.
type RefreshTokenFamilyStatus struct {
	// LastUsedAt is when this family was last used (most recent rotation).
	LastUsedAt time.Time `json:"last_used_at,omitempty"`

	// UsageCount tracks legitimate token rotations in this family.
	// Incremented on each successful refresh grant.
	UsageCount int `json:"usage_count"`

	// ReplayDetectedAt is when a replay attack was detected (old token reused).
	// Per NIST SP 800-63-4, replay detection MUST revoke the entire family.
	ReplayDetectedAt *time.Time `json:"replay_detected_at,omitempty"`

	// RevokedAt is when this family was revoked (after replay detection).
	// Once revoked, all tokens in this family are invalid.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

func (r *RefreshTokenFamily) GetKind() string {
	return "RefreshTokenFamily"
}

func (r *RefreshTokenFamily) GetName() string {
	return r.Metadata.Name
}

func (r *RefreshTokenFamily) GetUID() string {
	return r.Metadata.UID
}

func (r *RefreshTokenFamily) IsHub() {}
