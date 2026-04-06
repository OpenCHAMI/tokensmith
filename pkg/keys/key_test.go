// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyManager(t *testing.T) {
	km := NewKeyManager()
	require.NotNil(t, km)

	t.Run("GenerateKeyPair with FIPS-compliant key size", func(t *testing.T) {
		err := km.GenerateRSAKeyPair()
		require.NoError(t, err)

		// Verify key size
		privateKey, err := km.GetRSAPrivateKey()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, privateKey.N.BitLen(), MinRSAKeySize)
	})

	t.Run("GenerateECKeyPair with FIPS-compliant curve", func(t *testing.T) {
		err := km.GenerateECKeyPair()
		require.NoError(t, err)

		// Verify curve
		privateKey, ok := km.privateKey.(*ecdsa.PrivateKey)
		require.True(t, ok)
		assert.GreaterOrEqual(t, privateKey.Curve.Params().BitSize, 256) // P-256 minimum
	})

	t.Run("SetKeyPair with non-compliant key size", func(t *testing.T) {
		// Generate a small RSA key
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024) // Below FIPS minimum
		require.NoError(t, err)

		err = km.SetKeyPair(smallKey, &smallKey.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "below minimum required")
	})

	t.Run("SetECKeyPair with non-compliant curve", func(t *testing.T) {
		// Generate a key with P-224 curve (below FIPS minimum)
		smallKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)

		err = km.SetECKeyPair(smallKey, &smallKey.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "below minimum required")
	})

	t.Run("Save and Load RSA keys", func(t *testing.T) {
		// Create temp directory
		tempDir, err := os.MkdirTemp("", "key-test")
		require.NoError(t, err)
		defer func() {
			_ = os.RemoveAll(tempDir)
		}() // Generate and save keys
		err = km.GenerateRSAKeyPair()
		require.NoError(t, err)

		privateKeyPath := filepath.Join(tempDir, "private.pem")
		publicKeyPath := filepath.Join(tempDir, "public.pem")

		err = km.SavePrivateKey(privateKeyPath)
		require.NoError(t, err)
		err = km.SavePublicKey(publicKeyPath)
		require.NoError(t, err)

		// Create new key manager and load keys
		newKm := NewKeyManager()
		err = newKm.LoadPrivateKey(privateKeyPath)
		require.NoError(t, err)
		err = newKm.LoadPublicKey(publicKeyPath)
		require.NoError(t, err)

		// Verify keys match
		originalPrivate, err := km.GetRSAPrivateKey()
		require.NoError(t, err)
		loadedPrivate, err := newKm.GetRSAPrivateKey()
		require.NoError(t, err)
		assert.Equal(t, originalPrivate.N, loadedPrivate.N)
	})

	t.Run("GetKeyPair with no keys set", func(t *testing.T) {
		emptyKm := NewKeyManager()
		_, err := emptyKm.GetPrivateKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not set")

		_, err = emptyKm.GetPublicKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not set")
	})

	t.Run("GetRSAPrivateKey with wrong key type", func(t *testing.T) {
		// Set ECDSA key
		err := km.GenerateECKeyPair()
		require.NoError(t, err)

		// Try to get as RSA key
		_, err = km.GetRSAPrivateKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not an RSA key")
	})

	t.Run("GetRSAPublicKey with wrong key type", func(t *testing.T) {
		// Set ECDSA key
		err := km.GenerateECKeyPair()
		require.NoError(t, err)

		// Try to get as RSA key
		_, err = km.GetRSAPublicKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not an RSA key")
	})
}

func TestRFC7638Thumbprint_IsDeterministicAndValid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid1, err := RFC7638Thumbprint(&priv.PublicKey)
	require.NoError(t, err)
	kid2, err := RFC7638Thumbprint(&priv.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, kid1, kid2)
	assert.True(t, IsRFC7638Thumbprint(kid1))

	raw, err := base64.RawURLEncoding.DecodeString(kid1)
	require.NoError(t, err)
	assert.Len(t, raw, sha256.Size)
}

func TestRFC7638Thumbprint_DifferentKeysDifferentKIDs(t *testing.T) {
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid1, err := RFC7638Thumbprint(&priv1.PublicKey)
	require.NoError(t, err)
	kid2, err := RFC7638Thumbprint(&priv2.PublicKey)
	require.NoError(t, err)

	assert.NotEqual(t, kid1, kid2)
}

func TestRFC7638Thumbprint_InvalidFormatRejected(t *testing.T) {
	assert.False(t, IsRFC7638Thumbprint(""))
	assert.False(t, IsRFC7638Thumbprint("openchami-abc-123"))
	assert.False(t, IsRFC7638Thumbprint("dG9vLXNob3J0"))
	assert.False(t, IsRFC7638Thumbprint("Zm9vYmFy="))
}
