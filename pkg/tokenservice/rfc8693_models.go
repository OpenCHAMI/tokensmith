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
	// Other RFC 8693 parameters (not used in bootstrap):
	// ActorToken, ActorTokenType, Scope, Resource, Audience
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
type BootstrapTokenPolicy struct {
	// Identity
	ID string // Opaque random token ID (for audit logs only, not the token itself)

	// Policy
	Subject    string        // Service requesting access (e.g., "boot-service")
	Audience   string        // Target service (e.g., "hsm", "smd")
	Scopes     []string      // Pre-authorized scopes (immutable, RFC 8693 Section 6)
	TTL        time.Duration // Bootstrap token lifetime
	RefreshTTL time.Duration // Maximum lifetime for issued refresh tokens (RFC 6749 Section 6)

	// Storage
	TokenHash string // SHA-256(bootstrap_token) for atomic validation

	// Lifecycle
	CreatedAt    time.Time
	ExpiresAt    time.Time
	ConsumedAt   *time.Time // Nil until redeemed
	ConsumedByIP string     // Audit: client IP on redemption

	// Replay protection
	ReplayAttempts    []time.Time // Track failed attempts for rate limiting
	BindingIdentifier string      // Optional: pod/instance ID for audit

	// Issued tokens
	IssuedAccessTokenID  string // Opaque token ID of resulting access token
	IssuedRefreshTokenID string // Opaque token ID of resulting refresh token
}

// HashBootstrapToken computes SHA-256(token) per RFC 8693 best practices.
// Bootstrap tokens are opaque and one-time-use; we store only the hash.
func HashBootstrapToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// RefreshTokenFamily tracks refresh token rotation for replay detection.
// See: NIST SP 800-63-4 Section 6.2.3 (Token Rotation and Family Tracking)
type RefreshTokenFamily struct {
	// Family identity
	FamilyID string // Shared across all rotations in this family

	// Current state
	CurrentTokenHash string // SHA-256(currently-valid-refresh-token)

	// Policy
	Subject  string   // Service ID
	Audience string   // Target service
	Scopes   []string // Original scopes (immutable)

	// Lifecycle
	IssuedAt  time.Time
	ExpiresAt time.Time

	// Usage tracking
	LastUsedAt       time.Time
	UsageCount       int        // Track legitimate rotations
	ReplayDetectedAt *time.Time // If replayed token from old generation presented
	RevokedAt        *time.Time // If family revoked after replay detection

	// Operator context
	BindingIdentifier string // Optional: pod/instance ID
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
