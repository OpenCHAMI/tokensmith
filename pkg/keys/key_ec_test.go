// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRFC7638Thumbprint_ECCoordinatesAreFixedWidth(t *testing.T) {
	tests := []struct {
		name            string
		curve           elliptic.Curve
		coordinateBytes int
	}{
		{name: "P-256", curve: elliptic.P256(), coordinateBytes: 32},
		{name: "P-384", curve: elliptic.P384(), coordinateBytes: 48},
		{name: "P-521", curve: elliptic.P521(), coordinateBytes: 66},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var privateKey *ecdsa.PrivateKey
			for scalar := uint64(1); scalar <= 4096; scalar++ {
				rawPrivateKey := make([]byte, tt.coordinateBytes)
				binary.BigEndian.PutUint64(rawPrivateKey[len(rawPrivateKey)-8:], scalar)

				candidate, err := ecdsa.ParseRawPrivateKey(tt.curve, rawPrivateKey)
				require.NoError(t, err)

				publicKeyBytes, err := candidate.PublicKey.Bytes()
				require.NoError(t, err)
				if publicKeyBytes[1] == 0 || publicKeyBytes[1+tt.coordinateBytes] == 0 {
					privateKey = candidate
					break
				}
			}
			require.NotNil(t, privateKey, "deterministic search did not find a leading-zero coordinate")

			canonicalJWK, err := canonicalJWKForThumbprint(&privateKey.PublicKey)
			require.NoError(t, err)

			var jwk struct {
				Curve string `json:"crv"`
				Type  string `json:"kty"`
				X     string `json:"x"`
				Y     string `json:"y"`
			}
			require.NoError(t, json.Unmarshal([]byte(canonicalJWK), &jwk))
			assert.Equal(t, tt.name, jwk.Curve)
			assert.Equal(t, "EC", jwk.Type)

			x, err := base64.RawURLEncoding.DecodeString(jwk.X)
			require.NoError(t, err)
			y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
			require.NoError(t, err)
			assert.Len(t, x, tt.coordinateBytes)
			assert.Len(t, y, tt.coordinateBytes)

			encodedPublicKey := make([]byte, 1, 1+len(x)+len(y))
			encodedPublicKey[0] = 4
			encodedPublicKey = append(encodedPublicKey, x...)
			encodedPublicKey = append(encodedPublicKey, y...)
			reconstructed, err := ecdsa.ParseUncompressedPublicKey(tt.curve, encodedPublicKey)
			require.NoError(t, err)

			digest := sha256.Sum256([]byte("OpenCHAMI EC JWK regression"))
			signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
			require.NoError(t, err)
			assert.True(t, ecdsa.VerifyASN1(reconstructed, digest[:], signature))
		})
	}
}

func TestRFC7638Thumbprint_MalformedECPublicKeysReturnErrors(t *testing.T) {
	rawPrivateKey := make([]byte, 28)
	rawPrivateKey[len(rawPrivateKey)-1] = 1
	unsupportedCurveKey, err := ecdsa.ParseRawPrivateKey(elliptic.P224(), rawPrivateKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		publicKey *ecdsa.PublicKey
	}{
		{name: "nil public key", publicKey: nil},
		{name: "missing coordinates", publicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}},
		{name: "unsupported curve", publicKey: &unsupportedCurveKey.PublicKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var thumbprintErr error
			require.NotPanics(t, func() {
				_, thumbprintErr = RFC7638Thumbprint(tt.publicKey)
			})
			require.Error(t, thumbprintErr)
		})
	}
}
