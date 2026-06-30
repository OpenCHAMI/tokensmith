// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// RFC 8693 Token Exchange Types
// See: https://datatracker.ietf.org/doc/html/rfc8693

const (
	// Grant types (RFC 8693 Section 2)
	GrantTypeTokenExchange       = "urn:ietf:params:oauth:grant-type:token-exchange"
	GrantTypeRefreshTokenRFC8693 = "refresh_token" // RFC 6749 Section 6

	// Token types (RFC 8693 Section 3)
	BootstrapTokenTypeRFC8693 = "urn:openchami:params:oauth:token-type:bootstrap-token"
	AccessTokenTypeRFC8693    = "urn:ietf:params:oauth:token-type:access-token"
	RefreshTokenTypeRFC8693   = "urn:ietf:params:oauth:token-type:refresh-token"

	// RFC 8693 Response fields
	IssuedTokenTypeField = "issued_token_type"
)

// OAuthTokenRequest is the RFC 8693 token request.
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.1
type OAuthTokenRequest struct {
	GrantType        string `json:"grant_type"`
	SubjectToken     string `json:"subject_token,omitempty"`
	SubjectTokenType string `json:"subject_token_type,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	ParentTokenID    string `json:"parent_token_id,omitempty"`
}

// OAuthTokenResponse is the RFC 8693 token response.
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2.2 and RFC 6749 Section 5.1
type OAuthTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IssuedTokenType  string `json:"issued_token_type"`
}

// OAuthErrorResponse is the RFC 6749 error response.
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// BootstrapTokenPolicy stores server-side policy for opaque bootstrap tokens.
// The bootstrap token itself is never stored; only its SHA-256 hash is persisted.
//
// Storage Strategy:
// - PostgreSQL table: bootstrap_token_policies (dedicated table per type)
// - Primary key: ID (random opaque identifier)
// - Critical indexes: token_hash (O(1) validation), subject (audit queries), expires_at (cleanup)
// - Immutable fields: Policy never changes after creation (RFC 8693 Section 6)
// - Security: TokenHash never exposed in API responses
//
// +fabrica:storage=dedicated
// +fabrica:storage:backend=postgres
// +fabrica:storage:table=bootstrap_token_policies
// +fabrica:index:token_hash
// +fabrica:index:subject
// +fabrica:index:expires_at
type BootstrapTokenPolicy struct {
	// Identity
	// +fabrica:field:immutable
	ID string `json:"id"` // Opaque random token ID (for audit logs only, not the token itself)

	// Policy (immutable per RFC 8693 Section 6)
	// +fabrica:field:immutable
	Subject string `json:"subject"` // Service requesting access (e.g., "boot-service")

	// +fabrica:field:immutable
	Audience string `json:"audience"` // Target service (e.g., "hsm", "smd")

	// +fabrica:field:immutable
	Scopes []string `json:"scopes"` // Pre-authorized scopes (immutable, RFC 8693 Section 6)

	// +fabrica:field:immutable
	TTL time.Duration `json:"ttl"` // Bootstrap token lifetime

	// +fabrica:field:immutable
	RefreshTTL time.Duration `json:"refresh_ttl"` // Maximum lifetime for issued refresh tokens (RFC 6749 Section 6)

	// Storage (security-critical field)
	// +fabrica:field:unique
	// +fabrica:field:immutable
	TokenHash string `json:"-"` // SHA-256(bootstrap_token) for atomic validation (NEVER expose in API)

	// Lifecycle
	// +fabrica:field:immutable
	CreatedAt time.Time `json:"created_at"`

	// +fabrica:field:immutable
	ExpiresAt time.Time `json:"expires_at"`

	ConsumedAt   *time.Time `json:"consumed_at,omitempty"`    // Nil until redeemed
	ConsumedByIP string     `json:"consumed_by_ip,omitempty"` // Audit: client IP on redemption

	// Replay protection
	ReplayAttempts    []time.Time `json:"replay_attempts,omitempty"`    // Track failed attempts for rate limiting
	BindingIdentifier string      `json:"binding_identifier,omitempty"` // Optional: pod/instance ID for audit

	// Issued tokens
	IssuedAccessTokenID  string `json:"issued_access_token_id,omitempty"`  // Opaque token ID of resulting access token
	IssuedRefreshTokenID string `json:"issued_refresh_token_id,omitempty"` // Opaque token ID of resulting refresh token
}

// HashBootstrapToken computes SHA-256(token) per RFC 8693 best practices.
// Bootstrap tokens are opaque and one-time-use; we store only the hash.
func HashBootstrapToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// RefreshTokenFamily tracks refresh token rotation for replay detection.
// See: NIST SP 800-63-4 Section 6.2.3 (Token Rotation and Family Tracking)
//
// Storage Strategy:
// - PostgreSQL table: refresh_token_families (dedicated table per type)
// - Primary key: FamilyID (stable family identifier)
// - Critical indexes: current_token_hash (O(1) token lookup - fixes O(n) file scan!), subject, expires_at
// - Immutable policy: Original grant scopes/audience never change (NIST 800-63-4)
// - Security: CurrentTokenHash never exposed (only server knows valid token)
//
// Performance improvement: GetFamilyByTokenHash() is currently O(n) file scan.
// With indexed CurrentTokenHash, this becomes O(1) database lookup.
//
// +fabrica:storage=dedicated
// +fabrica:storage:backend=postgres
// +fabrica:storage:table=refresh_token_families
// +fabrica:index:current_token_hash
// +fabrica:index:subject
// +fabrica:index:expires_at
type RefreshTokenFamily struct {
	// Family identity
	// +fabrica:field:immutable
	FamilyID string `json:"family_id"` // Shared across all rotations in this family

	// Current state (security-critical: enables token validation)
	// +fabrica:field:unique
	CurrentTokenHash string `json:"-"` // SHA-256(currently-valid-refresh-token) - NEVER expose in API

	// Policy (immutable per NIST SP 800-63-4)
	// +fabrica:field:immutable
	Subject string `json:"subject"` // Service ID

	// +fabrica:field:immutable
	Audience string `json:"audience"` // Target service

	// +fabrica:field:immutable
	Scopes []string `json:"scopes"` // Original scopes (immutable)

	// Lifecycle
	// +fabrica:field:immutable
	IssuedAt time.Time `json:"issued_at"`

	// +fabrica:field:immutable
	ExpiresAt time.Time `json:"expires_at"`

	// Usage tracking (mutable: updated on each rotation)
	LastUsedAt       time.Time  `json:"last_used_at"`
	UsageCount       int        `json:"usage_count"`                  // Track legitimate rotations
	ReplayDetectedAt *time.Time `json:"replay_detected_at,omitempty"` // If replayed token from old generation presented
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`         // If family revoked after replay detection

	// Operator context
	BindingIdentifier string `json:"binding_identifier,omitempty"` // Optional: pod/instance ID
}

// IsExpired checks if the bootstrap token policy has expired.
// Per RFC 6749 and NIST SP 800-63, token expiry is non-negotiable.
func (b *BootstrapTokenPolicy) IsExpired() bool {
	return time.Now().After(b.ExpiresAt)
}

// IsConsumed checks if the bootstrap token has already been redeemed.
// Per NIST SP 800-63, bootstrap tokens are single-use.
func (b *BootstrapTokenPolicy) IsConsumed() bool {
	return b.ConsumedAt != nil
}

// IsExpired checks if the refresh token family has expired.
func (r *RefreshTokenFamily) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsRevoked checks if the refresh token family has been revoked (replay detected).
func (r *RefreshTokenFamily) IsRevoked() bool {
	return r.RevokedAt != nil
}
