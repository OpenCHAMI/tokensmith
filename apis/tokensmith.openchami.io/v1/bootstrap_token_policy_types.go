// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package v1

import (
	"time"

	"github.com/openchami/fabrica/pkg/resource"
)

// BootstrapTokenPolicy is a Fabrica resource for bootstrap token policies.
//
// This resource represents server-side policy for opaque bootstrap tokens used in
// service-to-service authentication. Bootstrap tokens are one-time-use credentials
// that exchange for access/refresh token pairs.
//
// Storage Strategy:
// - Dedicated PostgreSQL table: bootstrap_token_policies
// - O(1) token validation via indexed TokenHash
// - Immutable policy (RFC 8693 Section 6 compliance)
// - Mutable state tracking in Status (consumed, replay attempts)
//
// Security:
// - Token hashes never exposed in API (json:"-")
// - Immutable policy prevents privilege escalation
// - Unique constraint prevents duplicate tokens
//
// +fabrica:resource
// +fabrica:storage=dedicated
// +fabrica:storage:backend=postgres
// +fabrica:storage:table=bootstrap_token_policies
// +fabrica:index:token_hash
// +fabrica:index:subject
// +fabrica:index:expires_at
type BootstrapTokenPolicy struct {
	APIVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   resource.Metadata          `json:"metadata"`
	Spec       BootstrapTokenPolicySpec   `json:"spec" validate:"required"`
	Status     BootstrapTokenPolicyStatus `json:"status,omitempty"`
}

// BootstrapTokenPolicySpec defines the immutable policy for a bootstrap token.
// Per RFC 8693 Section 6, bootstrap token policies are immutable after creation.
type BootstrapTokenPolicySpec struct {
	// Subject identifies the service requesting access (e.g., "boot-service", "magellan")
	// +fabrica:field:immutable
	// +fabrica:field:index
	Subject string `json:"subject" validate:"required"`

	// Audience identifies the target service (e.g., "hsm", "smd", "inventory")
	// +fabrica:field:immutable
	Audience string `json:"audience" validate:"required"`

	// Scopes are the pre-authorized scopes for the resulting tokens.
	// Per RFC 8693 Section 6, scopes are immutable.
	// +fabrica:field:immutable
	Scopes []string `json:"scopes" validate:"required,min=1"`

	// TTL is the bootstrap token lifetime (nanoseconds).
	// +fabrica:field:immutable
	TTL int64 `json:"ttl" validate:"required,gt=0"`

	// RefreshTTL is the maximum lifetime for issued refresh tokens (nanoseconds).
	// Per RFC 6749 Section 6.
	// +fabrica:field:immutable
	RefreshTTL int64 `json:"refresh_ttl" validate:"required,gt=0"`

	// TokenHash is SHA-256(bootstrap_token) for atomic validation.
	// SECURITY: Never expose this field in API responses.
	// +fabrica:field:immutable
	// +fabrica:field:unique
	// +fabrica:field:index
	TokenHash string `json:"-"`

	// ExpiresAt is when this bootstrap token expires.
	// +fabrica:field:immutable
	// +fabrica:field:index
	ExpiresAt time.Time `json:"expires_at" validate:"required"`

	// BindingIdentifier is optional metadata for audit (e.g., pod/instance ID)
	BindingIdentifier string `json:"binding_identifier,omitempty"`
}

// BootstrapTokenPolicyStatus tracks the mutable state of a bootstrap token.
// This includes consumption status and replay protection tracking.
type BootstrapTokenPolicyStatus struct {
	// ConsumedAt is when this bootstrap token was redeemed.
	// Nil until first use (one-time-use per NIST SP 800-63).
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`

	// ConsumedByIP is the client IP address that redeemed this token.
	// Used for audit trails.
	ConsumedByIP string `json:"consumed_by_ip,omitempty"`

	// ReplayAttempts tracks failed redemption attempts (replay attacks).
	// Each element is a timestamp of a replay attempt.
	ReplayAttempts []time.Time `json:"replay_attempts,omitempty"`

	// IssuedAccessTokenID is the opaque ID of the access token issued in exchange.
	IssuedAccessTokenID string `json:"issued_access_token_id,omitempty"`

	// IssuedRefreshTokenID is the opaque ID of the refresh token issued in exchange.
	IssuedRefreshTokenID string `json:"issued_refresh_token_id,omitempty"`
}

func (r *BootstrapTokenPolicy) GetKind() string {
	return "BootstrapTokenPolicy"
}

func (r *BootstrapTokenPolicy) GetName() string {
	return r.Metadata.Name
}

func (r *BootstrapTokenPolicy) GetUID() string {
	return r.Metadata.UID
}

func (r *BootstrapTokenPolicy) IsHub() {}
