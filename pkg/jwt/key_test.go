package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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
		defer os.RemoveAll(tempDir)

		// Generate and save keys
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
