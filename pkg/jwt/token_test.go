package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenOperations(t *testing.T) {
	// Create a key manager for testing
	km := NewKeyManager()
	require.NotNil(t, km)

	// Generate a new key pair for testing
	err := km.GenerateKeyPair(2048)
	require.NoError(t, err)

	// Create token manager
	tm := NewTokenManager(km, "test-issuer")
	require.NotNil(t, tm)

	t.Run("GenerateToken with standard claims", func(t *testing.T) {
		claims := &Claims{
			Issuer:         "test-issuer",
			Subject:        "test-subject",
			Audience:       []string{"test-audience"},
			ExpirationTime: time.Now().Add(time.Hour).Unix(),
			NotBefore:      time.Now().Unix(),
			IssuedAt:       time.Now().Unix(),
			Scope:          []string{"read", "write"},
			Name:           "Test User",
			Email:          "test@example.com",
			EmailVerified:  true,
		}

		token, err := tm.GenerateToken(claims)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify the token
		parsedClaims, rawClaims, err := tm.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, parsedClaims)
		require.NotNil(t, rawClaims)

		// Verify standard claims
		assert.Equal(t, claims.Issuer, parsedClaims.Issuer)
		assert.Equal(t, claims.Subject, parsedClaims.Subject)
		assert.Equal(t, claims.Audience, parsedClaims.Audience)
		assert.Equal(t, claims.Scope, parsedClaims.Scope)
		assert.Equal(t, claims.Name, parsedClaims.Name)
		assert.Equal(t, claims.Email, parsedClaims.Email)
		assert.Equal(t, claims.EmailVerified, parsedClaims.EmailVerified)
	})

	t.Run("GenerateTokenWithClaims with additional claims", func(t *testing.T) {
		claims := &Claims{
			Issuer:         "test-issuer",
			Subject:        "test-subject",
			Audience:       []string{"test-audience"},
			ExpirationTime: time.Now().Add(time.Hour).Unix(),
			NotBefore:      time.Now().Unix(),
			IssuedAt:       time.Now().Unix(),
		}

		additionalClaims := map[string]interface{}{
			"custom_claim":   "custom_value",
			"service_id":     "test-service",
			"target_service": "auth-service",
			"roles":          []string{"admin", "user"},
		}

		token, err := tm.GenerateTokenWithClaims(claims, additionalClaims)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify the token
		parsedClaims, rawClaims, err := tm.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, parsedClaims)
		require.NotNil(t, rawClaims)

		// Verify standard claims
		assert.Equal(t, claims.Issuer, parsedClaims.Issuer)
		assert.Equal(t, claims.Subject, parsedClaims.Subject)
		assert.Equal(t, claims.Audience, parsedClaims.Audience)

		// Verify additional claims
		assert.Equal(t, "custom_value", rawClaims["custom_claim"])
		assert.Equal(t, "test-service", rawClaims["service_id"])
		assert.Equal(t, "auth-service", rawClaims["target_service"])
		assert.Equal(t, []interface{}{"admin", "user"}, rawClaims["roles"])
	})

	t.Run("ParseToken with invalid token", func(t *testing.T) {
		invalidTokens := []string{
			"",                // Empty token
			"invalid",         // Not a JWT
			"header.body.sig", // Invalid JWT format
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature", // Invalid signature
		}

		for _, token := range invalidTokens {
			claims, rawClaims, err := tm.ParseToken(token)
			assert.Error(t, err)
			assert.Nil(t, claims)
			assert.Nil(t, rawClaims)
		}
	})

	t.Run("GenerateToken with expired token", func(t *testing.T) {
		claims := &Claims{
			Issuer:         "test-issuer",
			Subject:        "test-subject",
			Audience:       []string{"test-audience"},
			ExpirationTime: time.Now().Add(-time.Hour).Unix(), // Expired
			NotBefore:      time.Now().Add(-2 * time.Hour).Unix(),
			IssuedAt:       time.Now().Add(-2 * time.Hour).Unix(),
		}

		token, err := tm.GenerateToken(claims)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid claims")
	})

	t.Run("GenerateToken with future token", func(t *testing.T) {
		claims := &Claims{
			Issuer:         "test-issuer",
			Subject:        "test-subject",
			Audience:       []string{"test-audience"},
			ExpirationTime: time.Now().Add(2 * time.Hour).Unix(),
			NotBefore:      time.Now().Add(time.Hour).Unix(), // Not valid yet
			IssuedAt:       time.Now().Unix(),
		}

		token, err := tm.GenerateToken(claims)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid claims")
	})

	t.Run("GenerateTokenWithClaims with nil claims", func(t *testing.T) {
		additionalClaims := map[string]interface{}{
			"custom_claim": "custom_value",
		}

		// Should fail because default claims don't have required fields
		token, err := tm.GenerateTokenWithClaims(nil, additionalClaims)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid claims")

		// Now try with minimal valid claims
		claims := &Claims{
			Issuer:         "test-issuer",
			Subject:        "test-subject",
			Audience:       []string{"test-audience"},
			ExpirationTime: time.Now().Add(time.Hour).Unix(),
			NotBefore:      time.Now().Unix(),
			IssuedAt:       time.Now().Unix(),
		}

		token, err = tm.GenerateTokenWithClaims(claims, additionalClaims)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify the token
		parsedClaims, rawClaims, err := tm.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, parsedClaims)
		require.NotNil(t, rawClaims)

		// Verify standard claims
		assert.Equal(t, claims.Issuer, parsedClaims.Issuer)
		assert.Equal(t, claims.Subject, parsedClaims.Subject)
		assert.Equal(t, claims.Audience, parsedClaims.Audience)

		// Verify additional claims
		assert.Equal(t, "custom_value", rawClaims["custom_claim"])
	})
}
