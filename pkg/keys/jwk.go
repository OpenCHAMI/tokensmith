// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
)

// RFC7638Thumbprint computes a JWK thumbprint-style key ID (SHA-256, base64url)
// for supported public key types according to RFC 7638 canonical members.
func RFC7638Thumbprint(publicKey interface{}) (string, error) {
	canonicalJWK, err := canonicalJWKForThumbprint(publicKey)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256([]byte(canonicalJWK))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// IsRFC7638Thumbprint returns true when kid is a base64url-encoded SHA-256
// JWK thumbprint as produced by RFC7638Thumbprint.
func IsRFC7638Thumbprint(kid string) bool {
	if kid == "" {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(kid)
	if err != nil {
		return false
	}

	return len(raw) == sha256.Size
}

func canonicalJWKForThumbprint(publicKey interface{}) (string, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return canonicalRSAJWK(key), nil
	case rsa.PublicKey:
		return canonicalRSAJWK(&key), nil
	case *ecdsa.PublicKey:
		return canonicalECJWK(key)
	case ecdsa.PublicKey:
		return canonicalECJWK(&key)
	default:
		return "", fmt.Errorf("unsupported key type %T", publicKey)
	}
}

func canonicalRSAJWK(key *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		e,
		n,
	)
}

func canonicalECJWK(key *ecdsa.PublicKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("EC public key is nil")
	}

	curve, coordinateWidth, err := jwkCurve(key.Curve)
	if err != nil {
		return "", err
	}
	point, err := ecPublicKeyBytes(key)
	if err != nil {
		return "", fmt.Errorf("encode EC public key: %w", err)
	}
	if len(point) != 1+2*coordinateWidth {
		return "", fmt.Errorf("invalid EC public key length %d for %s", len(point), curve)
	}
	if point[0] != 4 {
		return "", fmt.Errorf("invalid EC public key prefix %d", point[0])
	}

	x := base64.RawURLEncoding.EncodeToString(point[1 : 1+coordinateWidth])
	y := base64.RawURLEncoding.EncodeToString(point[1+coordinateWidth:])
	return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
		curve,
		x,
		y,
	), nil
}

func ecPublicKeyBytes(key *ecdsa.PublicKey) (point []byte, err error) {
	defer func() {
		if recover() != nil {
			point = nil
			err = fmt.Errorf("EC public key is malformed")
		}
	}()

	return key.Bytes()
}

func jwkCurve(curve elliptic.Curve) (string, int, error) {
	switch curve {
	case elliptic.P256():
		return "P-256", 32, nil
	case elliptic.P384():
		return "P-384", 48, nil
	case elliptic.P521():
		return "P-521", 66, nil
	default:
		return "", 0, fmt.Errorf("unsupported EC curve")
	}
}
