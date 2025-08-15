// Package token defines types and utilities for JWT-based authentication in microservices.
// It supports standard JWT claims (RFC 7519), OpenID Connect fields (OIDC Core 1.0),
// OAuth2/JWT Bearer extensions (RFC 7523), and NIST SP 800-63B–compliant claims.
// All validation logic should follow JSON Web Token Best Current Practices (RFC 8725)
// for algorithm selection, header/claim validation, and cryptographic hygiene,
// using only FIPS 140-2 or FIPS 140-3–validated modules and approved algorithms.
package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims structure used for user authentication.
//
// Standards referenced:
//   - Core JWT:        RFC 7519 https://datatracker.ietf.org/doc/html/rfc7519
//   - JWT Bearer:      RFC 7523 https://datatracker.ietf.org/doc/html/rfc7523
//   - OpenID Connect:  Core 1.0 https://openid.net/specs/openid-connect-core-1_0.html#IDToken
//   - NIST SP 800-63B: §§5.2.4 (Authentication Context), session management
//   - JWT Best Practices: RFC 8725 (§3.1–3.5, §3.2 header & claim rules)
//   - FIPS 140-2/3:    Approved security functions (e.g., RSA-PSS, ECDSA P-256, AES-GCM) https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-3.pdf and https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.140-2.pdf
type TSClaims struct {
	jwt.RegisteredClaims // Embedded RegisteredClaims provides standard JWT fields like "iss", "sub", "aud", etc.
	// Issuer identifies the principal that issued the JWT.
	// JSON key: "iss"
	// RFC 7519 §4.1.1; RFC 8725 §3.2: verify that the verification key belongs to this issuer.
	// Sub identifies the principal that is the subject of the JWT (e.g., user ID).
	// JSON key: "sub"
	// RFC 7519 §4.1.2; RFC 8725 §3.2: ensure the subject is bound to the issuer.
	// Audience lists the recipients that the JWT is intended for.
	// JSON key: "aud"
	// RFC 7519 §4.1.3; RFC 8725 §3.2: reject if your service is not in this list.
	// ExpiresAt is the expiration time, in Unix seconds.
	// JSON key: "exp"
	// RFC 7519 §4.1.4; RFC 8725 §3.5: enforce expiration to guard against replay.
	// NotBefore is the "not before" time, in Unix seconds.
	// JSON key: "nbf"
	// RFC 7519 §4.1.5; RFC 8725 §3.5: enforce nbf to prevent early use.
	// IssuedAt is the time the JWT was issued, in Unix seconds.
	// JSON key: "iat"
	// RFC 7519 §4.1.6; RFC 8725 §3.5: use iat to detect stale tokens.
	// ID is a unique identifier for the JWT, for replay detection.
	// JSON key: "jti"
	// RFC 7519 §4.1.7; RFC 8725 §3.5: recommended for one-time or blacklisting schemes.

	// Nonce is an optional value to mitigate replay attacks in interactive flows.
	// JSON key: "nonce"
	// RFC 8725 §3.5: use when tokens may be replayed in browser-based contexts.
	Nonce string `json:"nonce,omitempty"`

	// Name is the end-user's full name.
	// JSON key: "name"
	// OIDC Core 1.0; include only if needed by downstream services.
	Name string `json:"name,omitempty"`

	// Email is the end-user's email address.
	// JSON key: "email"
	// OIDC Core 1.0; include only if needed by downstream services.
	Email string `json:"email,omitempty"`

	// EmailVerified indicates whether the email address is verified.
	// JSON key: "email_verified"
	// OIDC Core 1.0; RFC 8725 §3.2: consider as part of trust decisions.
	EmailVerified bool `json:"email_verified,omitempty"`

	// AuthTime is when the end-user authentication occurred, in Unix seconds.
	// JSON key: "auth_time"
	// OIDC Core 1.0 §2; RFC 8725 §3.5: use for step-up/auth freshness checks.
	AuthTime int64 `json:"auth_time,omitempty"`

	// AMR lists the authentication methods used (e.g., ["pwd","otp","fido2"]).
	// JSON key: "amr"
	// OIDC Core 1.0 §3; RFC 8725 §3.2: validate each method reference.
	AMR []string `json:"amr,omitempty"`

	// ACR indicates the authentication context class reference (e.g., "AAL2").
	// JSON key: "acr"
	// OIDC Core 1.0 §3; NIST SP 800-63B §5.2.4; RFC 8725 §3.2: ensure it meets policy.
	ACR string `json:"acr,omitempty"`

	// Scope lists permissions or scopes granted.
	// JSON key: "scope"
	// OAuth 2.0 JWT Bearer (RFC 7523); RFC 8725 §3.2: validate scopes against client entitlements.
	Scope []string `json:"scope,omitempty"`

	// AuthLevel indicates the Identity Assurance Level (IAL1, IAL2, IAL3).
	// JSON key: "auth_level"
	// NIST SP 800-63B §5.2.4; RFC 8725 §3.2: enforce minimum IAL for sensitive operations.
	AuthLevel string `json:"auth_level,omitempty"`

	// AuthFactors is the number of distinct auth factors presented.
	// JSON key: "auth_factors"
	// NIST SP 800-63B; RFC 8725 §3.2: require at least 2 factors for IAL2+.
	AuthFactors int `json:"auth_factors,omitempty"`

	// AuthMethods lists the methods used (e.g., ["password","sms","webauthn"]).
	// JSON key: "auth_methods"
	// NIST SP 800-63B §5.2.4; RFC 8725 §3.2: validate values before use.
	AuthMethods []string `json:"auth_methods,omitempty"`

	// SessionID is a unique session identifier for lifecycle management.
	// JSON key: "session_id"
	// NIST SP 800-63B session guidance; RFC 8725 §3.5: use for server-side session tracking.
	SessionID string `json:"session_id,omitempty"`

	// SessionExp is the session expiration, in Unix seconds.
	// JSON key: "session_exp"
	// NIST SP 800-63B session guidance; RFC 8725 §3.5: enforce max session duration.
	SessionExp int64 `json:"session_exp,omitempty"`

	// AuthEvents records past authentication events (e.g., ["login","reset_pwd"]).
	// JSON key: "auth_events"
	// NIST SP 800-63B; RFC 8725 §3.2: maintain history for anomaly detection.
	AuthEvents []string `json:"auth_events,omitempty"`

	// ClusterID is an OpenCHAMI claim for the requesting cluster.
	// JSON key: "cluster_id"
	ClusterID string `json:"cluster_id,omitempty"`

	// OpenCHAMIID is an OpenCHAMI claim for the unique entity ID.
	// JSON key: "openchami_id"
	OpenCHAMIID string `json:"openchami_id,omitempty"`
}

// NewClaims creates a new Claims instance with default timestamps:
// IssuedAt = now, NotBefore = now, ExpirationTime = now + 1h.
func NewClaims() *TSClaims {
	now := time.Now().Unix()
	return &TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Unix(now, 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(now, 0)),
			ExpiresAt: jwt.NewNumericDate(time.Unix(now+3600, 0)),
		},
		AuthFactors: 1, // default to at least one factor
		SessionExp:  now + 3600,
	}
}

// Validate checks if the claims are valid according to RFC 7519, RFC 8725, and NIST SP 800-63B.
func (c *TSClaims) Validate() error {
	now := time.Now()

	// Time-based checks (RFC 8725 §3.5)
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Time) {
		return ErrTokenExpired
	}
	if c.NotBefore != nil && now.Before(c.NotBefore.Time) {
		return ErrTokenNotValidYet
	}

	// Mandatory core claims (RFC 7519 §4.1)
	if c.Issuer == "" {
		return ErrMissingIssuer
	}
	if c.Subject == "" {
		return ErrMissingSubject
	}
	if len(c.Audience) == 0 {
		return ErrMissingAudience
	}

	// NIST SP 800-63B requirements
	if c.AuthLevel == "" {
		return errors.New("auth_level claim is required")
	}
	if c.AuthFactors < 2 {
		return errors.New("at least 2 authentication factors are required")
	}
	if len(c.AuthMethods) == 0 {
		return errors.New("auth_methods claim is required")
	}
	if c.SessionID == "" {
		return errors.New("session_id claim is required")
	}
	if c.SessionExp == 0 {
		return errors.New("session_exp claim is required")
	}
	iat := int64(0)
	if c.IssuedAt != nil {
		iat = c.IssuedAt.Time.Unix()
	}
	if c.SessionExp-iat > 86400 {
		return errors.New("session duration exceeds maximum allowed (24 hours)")
	}

	return nil
}
