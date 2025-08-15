package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenOperations(t *testing.T) {
	// Create a key manager for testing
	km := keys.NewKeyManager()
	require.NotNil(t, km)

	// Generate a new key pair for testing
	err := km.GenerateRSAKeyPair()
	require.NoError(t, err)

	// Create token manager
	tm := NewTokenManager(km, "test-issuer", "test-cluster-id", "test-openchami-id")
	require.NotNil(t, tm)

	// Get the RSA private key to verify it's the correct type
	privateKey, err := km.GetRSAPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Set the signing algorithm to RS256 since we're using RSA keys
	err = tm.SetSigningAlgorithm("RS256")
	require.NoError(t, err)

	// Verify default algorithm is FIPS-compliant
	assert.Equal(t, "RS256", tm.GetSigningAlgorithm())

	t.Run("SetSigningAlgorithm with FIPS-approved algorithms", func(t *testing.T) {
		// Test RSA algorithms (since we're using RSA keys)
		rsaAlgorithms := []string{
			"PS256", "PS384", "PS512", // RSASSA-PSS
			"RS256", "RS384", "RS512", // RSASSA-PKCS1-v1_5
		}

		for _, alg := range rsaAlgorithms {
			err := tm.SetSigningAlgorithm(alg)
			assert.NoError(t, err)
			assert.Equal(t, alg, tm.GetSigningAlgorithm())
		}

		// Test non-FIPS algorithm
		err := tm.SetSigningAlgorithm("HS256")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not FIPS-approved")
	})

	t.Run("SetSigningAlgorithm with ECDSA algorithms", func(t *testing.T) {
		// Create a new key manager for ECDSA testing
		ecKm := keys.NewKeyManager()
		require.NotNil(t, ecKm)

		// Generate ECDSA key pair for testing
		err := ecKm.GenerateECKeyPair()
		require.NoError(t, err)

		// Create token manager with ECDSA keys
		ecTm := NewTokenManager(ecKm, "test-issuer", "test-cluster-id", "test-openchami-id")
		require.NotNil(t, ecTm)

		// Test ECDSA algorithms
		ecdsaAlgorithms := []string{
			"ES256", "ES384", "ES512", // ECDSA
		}

		for _, alg := range ecdsaAlgorithms {
			err := ecTm.SetSigningAlgorithm(alg)
			assert.NoError(t, err)
			assert.Equal(t, alg, ecTm.GetSigningAlgorithm())
		}
	})

	t.Run("GenerateToken with standard claims", func(t *testing.T) {
		claims := &TSClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-issuer",
				Subject:   "test-subject",
				Audience:  []string{"test-audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Scope:         []string{"read", "write"},
			Name:          "Test User",
			Email:         "test@example.com",
			EmailVerified: true,
			// Add NIST-compliant claims
			AuthLevel:   "IAL2",
			AuthFactors: 2,
			AuthMethods: []string{"password", "mfa"},
			SessionID:   "test-session",
			SessionExp:  time.Now().Add(24 * time.Hour).Unix(),
			AuthEvents:  []string{"login", "mfa"},
		}

		token, err := tm.GenerateToken(claims)
		if err != nil {
			t.Fatalf("GenerateToken error: %v", err)
		}
		if token == "" {
			t.Fatalf("GenerateToken returned empty token")
		}
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

		// Verify NIST-compliant claims
		assert.Equal(t, claims.AuthLevel, parsedClaims.AuthLevel)
		assert.Equal(t, claims.AuthFactors, parsedClaims.AuthFactors)
		assert.Equal(t, claims.AuthMethods, parsedClaims.AuthMethods)
		assert.Equal(t, claims.SessionID, parsedClaims.SessionID)
		assert.Equal(t, claims.SessionExp, parsedClaims.SessionExp)
		assert.Equal(t, claims.AuthEvents, parsedClaims.AuthEvents)

		// Verify JTI and nonce are present
		assert.NotEmpty(t, rawClaims["jti"])
		assert.NotEmpty(t, rawClaims["nonce"])
	})

	t.Run("GenerateTokenWithClaims with additional claims", func(t *testing.T) {
		claims := &TSClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-issuer",
				Subject:   "test-subject",
				Audience:  []string{"test-audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			AuthLevel:   "IAL2",
			AuthFactors: 2,
			AuthMethods: []string{"password", "mfa"},
			SessionID:   "test-session",
			SessionExp:  time.Now().Add(24 * time.Hour).Unix(),
			AuthEvents:  []string{"login", "mfa"},
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
		parsedClaims := &TSClaims{}
		parsedToken, err := jwt.ParseWithClaims(token, parsedClaims, func(token *jwt.Token) (interface{}, error) {
			return tm.keyManager.GetPublicKey()
		})
		require.NoError(t, err)
		require.NotNil(t, parsedToken)
		require.NotNil(t, parsedClaims)

		// Parse raw claims as map[string]interface{}
		rawToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
		require.NoError(t, err)
		rawClaims, ok := rawToken.Claims.(jwt.MapClaims)
		require.True(t, ok)

		// Verify standard claims
		assert.Equal(t, claims.Issuer, parsedClaims.Issuer)
		assert.Equal(t, claims.Subject, parsedClaims.Subject)
		assert.Equal(t, claims.Audience, parsedClaims.Audience)

		// Verify additional claims in the raw claims map
		assert.Equal(t, "custom_value", rawClaims["custom_claim"])
		assert.Equal(t, "test-service", rawClaims["service_id"])
		assert.Equal(t, "auth-service", rawClaims["target_service"])
		assert.ElementsMatch(t, []interface{}{"admin", "user"}, rawClaims["roles"])
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
		claims := &TSClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-issuer",
				Subject:   "test-subject",
				Audience:  []string{"test-audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)), // Expired
				NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			},
			// Add required NIST claims to avoid missing field errors
			AuthLevel:   "IAL2",
			AuthFactors: 2,
			AuthMethods: []string{"password", "mfa"},
			SessionID:   "test-session",
			SessionExp:  time.Now().Add(24 * time.Hour).Unix(),
			AuthEvents:  []string{"login", "mfa"},
		}

		token, err := tm.GenerateToken(claims)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid claims")
	})

	t.Run("GenerateToken with future token", func(t *testing.T) {
		claims := &TSClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-issuer",
				Subject:   "test-subject",
				Audience:  []string{"test-audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(time.Hour)), // Not valid yet
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			// Add required NIST claims
			AuthLevel:   "IAL2",
			AuthFactors: 2,
			AuthMethods: []string{"password", "mfa"},
			SessionID:   "test-session",
			SessionExp:  time.Now().Add(24 * time.Hour).Unix(),
			AuthEvents:  []string{"login", "mfa"},
		}

		token, err := tm.GenerateToken(claims)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "invalid claims")
	})

	t.Run("GenerateTokenWithClaims with nil claims", func(t *testing.T) {
		additionalClaims := map[string]interface{}{
			"custom_claim":   "custom_value",
			"service_id":     "test-service",
			"target_service": "auth-service",
			"roles":          []string{"admin", "user"},
		}

		// Should fail because default claims don't have required fields
		token, err := tm.GenerateTokenWithClaims(nil, additionalClaims)
		assert.Error(t, err)
		assert.Empty(t, token)
		assert.Contains(t, err.Error(), "missing issuer claim")
	})
}
