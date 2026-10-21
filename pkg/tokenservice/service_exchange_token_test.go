// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenService(t *testing.T) {
	// Create a mock provider using the existing mock implementation
	mockProvider := oidc.NewMockProvider()
	mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		// Return a mock introspection response
		return &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "testuser",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Claims: map[string]interface{}{
				"sub": "testuser",
				"iss": "test-issuer",
				"aud": []string{"test-audience"},
				"groups": []string{
					"admin",
					"operator",
				},
			},
			TokenType: "Bearer",
		}, nil
	}
	mockProvider.GetProviderMetadataFunc = func(ctx context.Context) (*oidc.ProviderMetadata, error) {
		return &oidc.ProviderMetadata{
			Issuer:                "test-issuer",
			IntrospectionEndpoint: "http://test/introspect",
			JWKSURI:               "http://test/jwks",
			ScopesSupported:       []string{"read", "write"},
		}, nil
	}
	mockProvider.SupportsLocalIntrospectionFunc = func() bool {
		return false
	}
	mockProvider.GetJWKSFunc = func(ctx context.Context) (interface{}, error) {
		return map[string]interface{}{
			"keys": []interface{}{},
		}, nil
	}

	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Create key manager
	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	// Create token manager
	tokenManager := token.NewTokenManager(keyManager, "test-issuer", "test-cluster-id", "test-openchami-id", true)

	// Create configuration
	config := &Config{
		Issuer:           "test-issuer",
		ClusterID:        "test-cluster-id",
		OpenCHAMIID:      "test-openchami-id",
		OIDCIssuerURL:    "http://test-oidc",
		OIDCClientID:     "test-client",
		OIDCClientSecret: "test-secret",
		GroupScopes: map[string][]string{
			"admin":    {"read", "write", "admin"},
			"operator": {"read", "write"},
			"user":     {"read"},
		},
	}

	// Create and load temporary policy model and permission files
	tempDir := t.TempDir()
	modelPath := filepath.Join(tempDir, "model.conf")
	policyPath := filepath.Join(tempDir, "policy.csv")

	modelData := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

	policyData := `
user1, data1, read
user2, data1, write
	`

	if err := os.WriteFile(modelPath, []byte(modelData), 0644); err != nil {
		t.Fatalf("Failed to write model file: %v", err)
	}
	if err := os.WriteFile(policyPath, []byte(policyData), 0644); err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}

	// Create service
	service := &TokenService{
		TokenManager: tokenManager,
		Config:       *config,
		Issuer:       config.Issuer,
		ClusterID:    config.ClusterID,
		OpenCHAMIID:  config.OpenCHAMIID,
		OIDCProvider: mockProvider,
		GroupScopes:  config.GroupScopes,
	}

	t.Run("Token Exchange - Admin User", func(t *testing.T) {
		// Configure mock to return admin user response
		service.OIDCProvider.(*oidc.MockProvider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "admin-user",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				Claims: map[string]interface{}{
					"sub":          "admin-user",
					"iss":          "test-issuer",
					"aud":          []string{"test-audience"},
					"groups":       []interface{}{"admin"},
					"auth_level":   "IAL2",
					"auth_factors": float64(2),
					"auth_methods": []interface{}{"password", "mfa"},
					"session_id":   "test-session-123",
					"session_exp":  float64(time.Now().Add(24 * time.Hour).Unix()),
					"auth_events":  []interface{}{"login", "mfa"},
				},
				TokenType: "Bearer",
			}, nil
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "admin-token")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, _, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		assert.Equal(t, "admin-user", claims.Subject)
		assert.Contains(t, claims.Scope, "read")
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "admin")
		require.NotEmpty(t, service.GroupScopes["admin"])
	})

	t.Run("Token Exchange - Operator User", func(t *testing.T) {
		// Configure mock to return operator user response
		service.OIDCProvider.(*oidc.MockProvider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "operator-user",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				Claims: map[string]interface{}{
					"sub":          "operator-user",
					"iss":          "test-issuer",
					"aud":          []string{"test-audience"},
					"groups":       []interface{}{"operator"},
					"auth_level":   "IAL2",
					"auth_factors": float64(2),
					"auth_methods": []interface{}{"password", "mfa"},
					"session_id":   "test-session-456",
					"session_exp":  float64(time.Now().Add(24 * time.Hour).Unix()),
					"auth_events":  []interface{}{"login", "mfa"},
				},
				TokenType: "Bearer",
			}, nil
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "operator-token")
		require.NoError(t, err)
		require.NotEmpty(t, token)

		// Parse and verify token
		claims, _, err := service.TokenManager.ParseToken(token)
		require.NoError(t, err)
		assert.Equal(t, "operator-user", claims.Subject)
		assert.Contains(t, claims.Scope, "read")
		assert.Contains(t, claims.Scope, "write")
		assert.NotContains(t, claims.Scope, "admin") // operator should not have admin access
		require.NotEmpty(t, service.GroupScopes["operator"])
	})

	t.Run("Token Exchange - Invalid Token", func(t *testing.T) {
		// Configure mock to return inactive token
		service.OIDCProvider.(*oidc.MockProvider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			return &oidc.IntrospectionResponse{
				Active:    false,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(-time.Hour).Unix(), // expired
				IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
				Claims:    make(map[string]interface{}),
				TokenType: "Bearer",
			}, nil
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "invalid-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token is not active")
	})

	t.Run("Token Exchange - Provider Error", func(t *testing.T) {
		// Configure mock to return an error
		service.OIDCProvider.(*oidc.MockProvider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			return nil, fmt.Errorf("provider error")
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "error-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token introspection failed")
	})

	t.Run("Token Exchange - Empty Token", func(t *testing.T) {
		// Exchange empty token
		token, err := service.ExchangeToken(context.Background(), "")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "empty token")
	})
}
