package jwt

import (
	"time"
)

// Claims represents the JWT claims structure
type Claims struct {
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	ExpirationTime int64    `json:"exp,omitempty"`
	NotBefore      int64    `json:"nbf,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
	JTI            string   `json:"jti,omitempty"`   // JWT ID to prevent replay attacks
	Nonce          string   `json:"nonce,omitempty"` // Additional replay protection
	Scope          []string `json:"scope,omitempty"`
	// Custom claims
	Name          string `json:"name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
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

// Validate checks if the claims are valid
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
