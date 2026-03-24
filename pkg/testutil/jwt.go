// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MintedJWT contains a signed token and the private key used to sign it.
//
// The key is returned so tests can wire a verifier/JWKS if needed.
//
// Note: this helper is intended for tests only.
type MintedJWT struct {
	Token      string
	PrivateKey *rsa.PrivateKey
}

// MintJWT signs arbitrary claims with a fresh RSA key and returns the signed
// token.
func MintJWT(claims jwt.Claims) (*MintedJWT, error) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(pk)
	if err != nil {
		return nil, err
	}

	return &MintedJWT{Token: signed, PrivateKey: pk}, nil
}

// StandardClaims returns a jwt.MapClaims pre-populated with common fields.
func StandardClaims(subject string, issuer string, audience []string, ttl time.Duration) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"sub": subject,
		"iss": issuer,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	}
}
