// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

// SessionTokenRequest represents the request body for POST /oauth/session
type SessionTokenRequest struct {
	// LifetimeSeconds specifies the lifetime of the session token in seconds.
	// Default: 43200 (12 hours)
	// Maximum: 86400 (24 hours per NIST SP 800-63B session guidance)
	LifetimeSeconds int64 `json:"lifetime_seconds,omitempty"`

	// ParentTokenID optionally links this session token to a parent token
	// for hierarchical token relationships (Issue #37).
	// If provided, MFA claims (amr, acr, auth_time) are inherited from the parent.
	ParentTokenID string `json:"parent_token_id,omitempty"`
}

// SessionTokenResponse represents the response body for POST /oauth/session
type SessionTokenResponse struct {
	// JWT is the issued session token (JWT format)
	JWT string `json:"jwt"`

	// TokenID is the unique identifier for this token (from jti claim)
	TokenID string `json:"token_id"`

	// ExpiresAt is the ISO 8601 timestamp when the token expires
	ExpiresAt string `json:"expires_at"`

	// SessionID is the OIDC session identifier linking this token to the auth session
	SessionID string `json:"session_id"`

	// AMR lists the authentication methods used (e.g., ["pwd", "otp"])
	// Extracted from the upstream OIDC id_token (Issue #34)
	AMR []string `json:"amr,omitempty"`

	// ACR is the authentication context class reference (e.g., "urn:okta:loa:2fa:any")
	// Extracted from the upstream OIDC id_token (Issue #34)
	ACR string `json:"acr,omitempty"`

	// AuthTime is the Unix timestamp when the user authenticated with the IdP
	// Extracted from the upstream OIDC id_token (Issue #34)
	AuthTime int64 `json:"auth_time,omitempty"`
}
