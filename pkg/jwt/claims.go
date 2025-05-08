package jwt

import (
	"errors"
	"time"
)

// Claims represents the JWT claims structure
type Claims struct {
	// Standard JWT claims
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	ExpirationTime int64    `json:"exp,omitempty"`
	NotBefore      int64    `json:"nbf,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
	JTI            string   `json:"jti,omitempty"`   // JWT ID to prevent replay attacks
	Nonce          string   `json:"nonce,omitempty"` // Additional replay protection

	// Standard OpenID Connect claims
	Name          string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	AuthTime      int64    `json:"auth_time,omitempty"`
	AMR           []string `json:"amr,omitempty"` // Authentication Methods References
	ACR           string   `json:"acr,omitempty"` // Authentication Context Class Reference

	// NIST SP 800-63B compliant claims
	AuthLevel   string   `json:"auth_level,omitempty"`   // IAL level (IAL1, IAL2, IAL3)
	AuthFactors int      `json:"auth_factors,omitempty"` // Number of authentication factors used
	AuthMethods []string `json:"auth_methods,omitempty"` // List of authentication methods used
	SessionID   string   `json:"session_id,omitempty"`   // Unique session identifier
	SessionExp  int64    `json:"session_exp,omitempty"`  // Session expiration time
	AuthEvents  []string `json:"auth_events,omitempty"`  // Authentication event history

	// OpenCHAMI specific claims
	ClusterID   string   `json:"cluster_id,omitempty"`
	OpenCHAMIID string   `json:"openchami_id,omitempty"`
	Scope       []string `json:"scope,omitempty"`
}

// ServiceClaims extends Claims for service-to-service communication
type ServiceClaims struct {
	Claims
	ServiceID     string   `json:"service_id,omitempty"`     // ID of the requesting service
	TargetService string   `json:"target_service,omitempty"` // ID of the target service
	ServiceScopes []string `json:"service_scopes,omitempty"` // Scopes specific to service-to-service communication
}

// NewClaims creates a new Claims instance with default values
func NewClaims() *Claims {
	now := time.Now().Unix()
	return &Claims{
		IssuedAt:       now,
		NotBefore:      now,
		ExpirationTime: now + 3600, // 1 hour default
	}
}

// Validate checks if the claims are valid according to NIST requirements
func (c *Claims) Validate() error {
	now := time.Now().Unix()

	// Check if token has expired
	if c.ExpirationTime != 0 && now > c.ExpirationTime {
		return ErrTokenExpired
	}

	// Check if token is not yet valid
	if c.NotBefore != 0 && now < c.NotBefore {
		return ErrTokenNotValidYet
	}

	// Check required claims
	if c.Issuer == "" {
		return ErrMissingIssuer
	}
	if c.Subject == "" {
		return ErrMissingSubject
	}
	if len(c.Audience) == 0 {
		return ErrMissingAudience
	}

	// Validate NIST requirements
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

	// Validate session duration
	if c.SessionExp-c.IssuedAt > 86400 { // 24 hours in seconds
		return errors.New("session duration exceeds maximum allowed (24 hours)")
	}

	// Validate authentication level
	if c.AuthLevel != "IAL1" && c.AuthLevel != "IAL2" && c.AuthLevel != "IAL3" {
		return errors.New("invalid auth_level value")
	}

	// Validate minimum authentication level
	if c.AuthLevel == "IAL1" {
		return errors.New("minimum authentication level IAL2 is required")
	}

	return nil
}

// SetExpiration sets the expiration time
func (c *Claims) SetExpiration(duration time.Duration) {
	c.ExpirationTime = time.Now().Add(duration).Unix()
}

// SetAudience sets the audience
func (c *Claims) SetAudience(audience []string) {
	c.Audience = audience
}

// SetScope sets the scope
func (c *Claims) SetScope(scope []string) {
	c.Scope = scope
}
