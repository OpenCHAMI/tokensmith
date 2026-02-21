//go:build test || !production
// +build test !production

package middleware

// Test helpers for generating ephemeral keys and signing JWTs during tests.
// These helpers are intended for use in unit/integration tests only and must
// never be used in production code. Placing them in _test.go files ensures
// they are only compiled during `go test`.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateRSAKey generates an ephemeral RSA private key suitable for signing
// RS256 tokens in tests.
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("insecure RSA key size: %d", bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateECDSAP256 generates a P-256 ECDSA private key for ES256 signing.
func GenerateECDSAP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SignTokenWithRSA signs the provided claims using RS256 and returns the
// compact JWT string.
func SignTokenWithRSA(claims jwt.Claims, priv *rsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", fmt.Errorf("private key is nil")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(priv)
}

// SignTokenWithECDSA signs the provided claims using ES256 and returns the
// compact JWT string.
func SignTokenWithECDSA(claims jwt.Claims, priv *ecdsa.PrivateKey) (string, error) {
	if priv == nil {
		return "", fmt.Errorf("private key is nil")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return token.SignedString(priv)
}

// PublicKeyFromRSA returns the public key corresponding to the RSA private key.
// Useful when wiring into JWT middleware that expects the public key.
func PublicKeyFromRSA(priv *rsa.PrivateKey) interface{} {
	if priv == nil {
		return nil
	}
	return &priv.PublicKey
}

// PublicKeyFromECDSA returns the public key corresponding to the ECDSA private key.
func PublicKeyFromECDSA(priv *ecdsa.PrivateKey) interface{} {
	if priv == nil {
		return nil
	}
	return &priv.PublicKey
}
