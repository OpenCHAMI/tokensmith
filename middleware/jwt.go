package middleware

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// ContextKey is the key used to store the claims in the context
type ContextKey string

const (
	// ClaimsContextKey is the key used to store the claims in the context
	ClaimsContextKey ContextKey = "jwt_claims"
	// RawClaimsContextKey is the key used to store raw claims in the context
	RawClaimsContextKey ContextKey = "jwt_raw_claims"
)

// Claims represents the JWT claims
type Claims struct {
	Issuer         string   `json:"iss,omitempty"`
	Subject        string   `json:"sub,omitempty"`
	Audience       []string `json:"aud,omitempty"`
	ExpirationTime int64    `json:"exp,omitempty"`
	NotBefore      int64    `json:"nbf,omitempty"`
	IssuedAt       int64    `json:"iat,omitempty"`
	Scope          []string `json:"scope,omitempty"`
	Name           string   `json:"name,omitempty"`
	Email          string   `json:"email,omitempty"`
	EmailVerified  bool     `json:"email_verified,omitempty"`
	ClusterID      string   `json:"cluster_id,omitempty"`
	OpenCHAMIID    string   `json:"openchami_id,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	RawClaims      map[string]interface{}
}

// Validate validates the claims
func (c *Claims) Validate() error {
	if c.ExpirationTime > 0 && time.Unix(c.ExpirationTime, 0).Before(time.Now()) {
		return errors.New("token has expired")
	}
	if c.NotBefore > 0 && time.Unix(c.NotBefore, 0).After(time.Now()) {
		return errors.New("token not yet valid")
	}
	return nil
}

// KeyManager manages JWT keys
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keySet     jwk.Set
}

// NewKeyManager creates a new KeyManager
func NewKeyManager() *KeyManager {
	return &KeyManager{}
}

// SetKeyPair sets the RSA key pair
func (km *KeyManager) SetKeyPair(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) error {
	km.privateKey = privateKey
	km.publicKey = publicKey
	return nil
}

// SetJWKS sets the JSON Web Key Set
func (km *KeyManager) SetJWKS(keySet jwk.Set) error {
	km.keySet = keySet
	return nil
}

// GenerateToken generates a new JWT token
func (km *KeyManager) GenerateToken(claims *Claims) (string, error) {
	if km.privateKey == nil {
		return "", fmt.Errorf("private key not set")
	}

	token := jwt.New()
	for k, v := range claims.RawClaims {
		if err := token.Set(k, v); err != nil {
			return "", fmt.Errorf("failed to set claim %s: %w", k, err)
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, km.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

// ParseToken parses and validates a JWT token
func (km *KeyManager) ParseToken(tokenString string) (*Claims, map[string]interface{}, error) {
	var key interface{}
	if km.keySet != nil {
		// Use JWKS for validation
		key = km.keySet
	} else if km.publicKey != nil {
		// Use public key for validation
		key = km.publicKey
	} else {
		return nil, nil, fmt.Errorf("no validation key available")
	}

	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKey(jwa.RS256, key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims := &Claims{
		Issuer:         token.Issuer(),
		Subject:        token.Subject(),
		Audience:       token.Audience(),
		ExpirationTime: token.Expiration().Unix(),
		NotBefore:      token.NotBefore().Unix(),
		IssuedAt:       token.IssuedAt().Unix(),
		RawClaims:      token.PrivateClaims(),
	}

	// Extract custom claims
	if scope, ok := claims.RawClaims["scope"].([]interface{}); ok {
		claims.Scope = make([]string, len(scope))
		for i, s := range scope {
			claims.Scope[i] = s.(string)
		}
	}

	if name, ok := claims.RawClaims["name"].(string); ok {
		claims.Name = name
	}

	if email, ok := claims.RawClaims["email"].(string); ok {
		claims.Email = email
	}

	if emailVerified, ok := claims.RawClaims["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}

	if clusterID, ok := claims.RawClaims["cluster_id"].(string); ok {
		claims.ClusterID = clusterID
	}

	if openCHAMIID, ok := claims.RawClaims["openchami_id"].(string); ok {
		claims.OpenCHAMIID = openCHAMIID
	}

	if groups, ok := claims.RawClaims["groups"].([]interface{}); ok {
		claims.Groups = make([]string, len(groups))
		for i, g := range groups {
			claims.Groups[i] = g.(string)
		}
	}

	return claims, claims.RawClaims, nil
}
