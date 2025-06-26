package middleware

import (
	"crypto/rsa"
	"fmt"

	gjwt "github.com/golang-jwt/jwt/v5"
	tsjwt "github.com/openchami/tokensmith/pkg/jwt"
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
	keySet     map[string]interface{} // map of kid to public key
}

// NewKeyManager creates a new KeyManager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		keySet: make(map[string]interface{}),
	}
}

// SetKeyPair sets the RSA key pair
func (km *KeyManager) SetKeyPair(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) error {
	km.privateKey = privateKey
	km.publicKey = publicKey
	return nil
}

// SetJWKS sets the JSON Web Key Set
func (km *KeyManager) SetJWKS(keySet map[string]interface{}) error {
	km.keySet = keySet
	return nil
}

// ParseToken parses and validates a JWT token
func (km *KeyManager) ParseToken(tokenString string) (*tsjwt.TSClaims, error) {
	// Create key function for token validation
	keyFunc := func(token *gjwt.Token) (interface{}, error) {
		// If JWKS is used, select key by kid
		if len(km.keySet) > 0 {
			if kid, ok := token.Header["kid"].(string); ok {
				if key, found := km.keySet[kid]; found {
					return key, nil
				}
				return nil, fmt.Errorf("key not found in JWKS for kid: %s", kid)
			}
			return nil, fmt.Errorf("no kid in token header")
		}
		// Use public key for validation
		if km.publicKey != nil {
			return km.publicKey, nil
		}
		return nil, fmt.Errorf("no validation key available")
	}

	// Parse token with claims
	claims := &tsjwt.TSClaims{}
	token, err := gjwt.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	return claims, nil
}
