package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/openchami/tokensmith/pkg/jwt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHydraClient struct {
	responses map[string]*jwt.HydraIntrospectResponse
}

func newMockHydraClient() *mockHydraClient {
	return &mockHydraClient{
		responses: make(map[string]*jwt.HydraIntrospectResponse),
	}
}

func (m *mockHydraClient) SetResponse(token string, response *jwt.HydraIntrospectResponse) {
	m.responses[token] = response
}

func (m *mockHydraClient) IntrospectToken(ctx context.Context, token string) (*jwt.HydraIntrospectResponse, error) {
	if response, ok := m.responses[token]; ok {
		return response, nil
	}
	return nil, jwt.ErrTokenIntrospectionFailed
}

func TestTokenService(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Create key manager
	keyManager := jwt.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	// Create mock Hydra client
	mockHydra := newMockHydraClient()

	// Create token service
	config := Config{
		HydraAdminURL: "http://mock-hydra",
		Issuer:        "https://openchami.example.com",
		Audience:      "smd,bss,cloud-init",
		GroupScopes: map[string][]string{
			"admin":    {"admin", "write", "read"},
			"operator": {"write", "read"},
			"viewer":   {"read"},
			"user":     {"read"},
		},
		ClusterID:   "test-cluster-id",
		OpenCHAMIID: "test-openchami-id",
	}

	// Create service with mock client
	service := &TokenService{
		TokenManager: jwt.NewTokenManager(keyManager, config.Issuer, config.ClusterID, config.OpenCHAMIID),
		Config:       config,
		HydraClient:  mockHydra,
		Issuer:       config.Issuer,
		Audience:     config.Audience,
		GroupScopes:  config.GroupScopes,
	}

	t.Run("Token Exchange - Admin User", func(t *testing.T) {
		// Set up mock response
		mockHydra.SetResponse("admin-token", &jwt.HydraIntrospectResponse{
			Active: true,
			Sub:    "admin-user",
			Ext: map[string]interface{}{
				"groups":         []interface{}{"admin"},
				"name":           "Admin User",
				"email":          "admin@example.com",
				"email_verified": true,
			},
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "admin-token")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, rawClaims, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, rawClaims)

		// Verify claims
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, "admin-user", claims.Subject)
		assert.Equal(t, []string{"test-audience"}, claims.Audience)
		assert.Equal(t, "Admin User", claims.Name)
		assert.Equal(t, "admin@example.com", claims.Email)
		assert.True(t, claims.EmailVerified)
		assert.Contains(t, claims.Scope, "admin")
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "read")
	})

	t.Run("Token Exchange - Operator User", func(t *testing.T) {
		// Set up mock response
		mockHydra.SetResponse("operator-token", &jwt.HydraIntrospectResponse{
			Active: true,
			Sub:    "operator-user",
			Ext: map[string]interface{}{
				"groups":         []interface{}{"operator"},
				"name":           "Operator User",
				"email":          "operator@example.com",
				"email_verified": true,
			},
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "operator-token")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, rawClaims, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, rawClaims)

		// Verify claims
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, "operator-user", claims.Subject)
		assert.Equal(t, []string{"test-audience"}, claims.Audience)
		assert.Equal(t, "Operator User", claims.Name)
		assert.Equal(t, "operator@example.com", claims.Email)
		assert.True(t, claims.EmailVerified)
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "read")
		assert.NotContains(t, claims.Scope, "admin")
	})

	t.Run("Token Exchange - Multiple Groups", func(t *testing.T) {
		// Set up mock response
		mockHydra.SetResponse("multi-group-token", &jwt.HydraIntrospectResponse{
			Active: true,
			Sub:    "multi-group-user",
			Ext: map[string]interface{}{
				"groups":         []interface{}{"admin", "operator"},
				"name":           "Multi Group User",
				"email":          "multi@example.com",
				"email_verified": true,
			},
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "multi-group-token")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, rawClaims, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, rawClaims)

		// Verify claims
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, "multi-group-user", claims.Subject)
		assert.Equal(t, []string{"test-audience"}, claims.Audience)
		assert.Equal(t, "Multi Group User", claims.Name)
		assert.Equal(t, "multi@example.com", claims.Email)
		assert.True(t, claims.EmailVerified)
		assert.Contains(t, claims.Scope, "admin")
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "read")
	})

	t.Run("Token Exchange - Invalid Token", func(t *testing.T) {
		// Set up mock response for inactive token
		mockHydra.SetResponse("invalid-token", &jwt.HydraIntrospectResponse{
			Active: false,
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "invalid-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token is not active")
	})

	t.Run("Token Exchange - Missing Groups", func(t *testing.T) {
		// Set up mock response without groups
		mockHydra.SetResponse("no-groups-token", &jwt.HydraIntrospectResponse{
			Active: true,
			Sub:    "no-groups-user",
			Ext: map[string]interface{}{
				"name":           "No Groups User",
				"email":          "nogroups@example.com",
				"email_verified": true,
			},
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "no-groups-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "no groups found in token")
	})

	t.Run("Token Exchange - Invalid Group Type", func(t *testing.T) {
		// Set up mock response with invalid group type
		mockHydra.SetResponse("invalid-group-token", &jwt.HydraIntrospectResponse{
			Active: true,
			Sub:    "invalid-group-user",
			Ext: map[string]interface{}{
				"groups":         []interface{}{123}, // Invalid group type
				"name":           "Invalid Group User",
				"email":          "invalid@example.com",
				"email_verified": true,
			},
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "invalid-group-token")
		require.NoError(t, err) // Should still succeed but with no scopes
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, rawClaims, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, rawClaims)

		// Verify no scopes were added
		assert.Empty(t, claims.Scope)
	})

	t.Run("Update Group Scopes", func(t *testing.T) {
		// Update group scopes
		newScopes := map[string][]string{
			"admin":    {"admin", "write", "read", "new-scope"},
			"operator": {"write", "read"},
		}
		service.UpdateGroupScopes(newScopes)

		// Set up mock response
		mockHydra.SetResponse("updated-scopes-token", &jwt.HydraIntrospectResponse{
			Active: true,
			Sub:    "admin-user",
			Ext: map[string]interface{}{
				"groups":         []interface{}{"admin"},
				"name":           "Admin User",
				"email":          "admin@example.com",
				"email_verified": true,
			},
		})

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "updated-scopes-token")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, rawClaims, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, rawClaims)

		// Verify new scope is present
		assert.Contains(t, claims.Scope, "new-scope")
	})

	t.Run("Token Exchange - Empty Token", func(t *testing.T) {
		// Exchange empty token
		token, err := service.ExchangeToken(context.Background(), "")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token introspection failed")
	})

	t.Run("Token Exchange - Hydra Error", func(t *testing.T) {
		// Exchange token with no mock response (will trigger error)
		token, err := service.ExchangeToken(context.Background(), "error-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token introspection failed")
	})
}
