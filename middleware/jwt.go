package middleware

import (
	"crypto/rsa"
	"fmt"

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

// ParseToken parses and validates a JWT token
func (km *KeyManager) ParseToken(tokenString string) (jwt.Token, error) {
	var key interface{}
	if km.keySet != nil {
		// Use JWKS for validation
		key = km.keySet
	} else if km.publicKey != nil {
		// Use public key for validation
		key = km.publicKey
	} else {
		return nil, fmt.Errorf("no validation key available")
	}

	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKey(jwa.RS256, key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, nil

}
