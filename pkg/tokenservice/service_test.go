// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestTokenService_GenerateServiceToken(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Create key manager
	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	// Create test cases
	tests := []struct {
		name           string
		config         Config
		serviceID      string
		targetService  string
		scopes         []string
		expectError    bool
		validateClaims func(*testing.T, *token.TSClaims)
	}{
		{
			name: "valid service token",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			serviceID:     "service1",
			targetService: "service2",
			scopes:        []string{"read", "write"},
			expectError:   false,
			validateClaims: func(t *testing.T, claims *token.TSClaims) {
				assert.Equal(t, "service1", claims.Subject)
				assert.Equal(t, "service2", claims.Audience[0])
				assert.Equal(t, []string{"read", "write"}, claims.Scope)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "test-issuer", claims.Issuer)
				assert.NotEmpty(t, claims.ExpiresAt)
				assert.NotEmpty(t, claims.IssuedAt)
				assert.NotEmpty(t, claims.NotBefore)
				// Verify NIST-compliant claims for service tokens
				assert.Equal(t, "IAL2", claims.AuthLevel)
				assert.Equal(t, 2, claims.AuthFactors)
				assert.Equal(t, []string{"service", "certificate"}, claims.AuthMethods)
				assert.NotEmpty(t, claims.SessionID)
				assert.NotEmpty(t, claims.SessionExp)
				assert.Equal(t, []string{"service_auth"}, claims.AuthEvents)
			},
		},
		{
			name: "empty scopes",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			serviceID:     "service1",
			targetService: "service2",
			scopes:        []string{},
			expectError:   false,
			validateClaims: func(t *testing.T, claims *token.TSClaims) {
				assert.Equal(t, "service1", claims.Subject)
				assert.Equal(t, "service2", claims.Audience[0])
				assert.Empty(t, claims.Scope)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "test-issuer", claims.Issuer)
				assert.NotEmpty(t, claims.ExpiresAt)
				assert.NotEmpty(t, claims.IssuedAt)
				assert.NotEmpty(t, claims.NotBefore)
				// Verify NIST-compliant claims for service tokens
				assert.Equal(t, "IAL2", claims.AuthLevel)
				assert.Equal(t, 2, claims.AuthFactors)
				assert.Equal(t, []string{"service", "certificate"}, claims.AuthMethods)
				assert.NotEmpty(t, claims.SessionID)
				assert.NotEmpty(t, claims.SessionExp)
				assert.Equal(t, []string{"service_auth"}, claims.AuthEvents)
			},
		},
		{
			name: "empty service ID",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			serviceID:     "",
			targetService: "service2",
			scopes:        []string{"read", "write"},
			expectError:   true,
		},
		{
			name: "empty target service",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			serviceID:     "service1",
			targetService: "",
			scopes:        []string{"read", "write"},
			expectError:   true,
		},
		{
			name: "nil scopes",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			serviceID:     "service1",
			targetService: "service2",
			scopes:        nil,
			expectError:   false,
			validateClaims: func(t *testing.T, claims *token.TSClaims) {
				assert.Equal(t, "service1", claims.Subject)
				assert.Equal(t, "service2", claims.Audience[0])
				assert.Nil(t, claims.Scope)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "test-issuer", claims.Issuer)
				assert.NotEmpty(t, claims.ExpiresAt)
				assert.NotEmpty(t, claims.IssuedAt)
				assert.NotEmpty(t, claims.NotBefore)
				// Verify NIST-compliant claims for service tokens
				assert.Equal(t, "IAL2", claims.AuthLevel)
				assert.Equal(t, 2, claims.AuthFactors)
				assert.Equal(t, []string{"service", "certificate"}, claims.AuthMethods)
				assert.NotEmpty(t, claims.SessionID)
				assert.NotEmpty(t, claims.SessionExp)
				assert.Equal(t, []string{"service_auth"}, claims.AuthEvents)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create token service
			service := &TokenService{
				TokenManager: token.NewTokenManager(keyManager, tt.config.Issuer, tt.config.ClusterID, tt.config.OpenCHAMIID, true),
				Config:       tt.config,
				Issuer:       tt.config.Issuer,
				ClusterID:    tt.config.ClusterID,
				OpenCHAMIID:  tt.config.OpenCHAMIID,
			}

			// Generate service token
			token, err := service.MintServiceToken(context.Background(), tt.serviceID, tt.targetService, tt.scopes)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Parse and validate claims
			claims, _, err := service.TokenManager.ParseToken(token)
			assert.NoError(t, err)
			tt.validateClaims(t, claims)

			parsedToken, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
			assert.NoError(t, err)
			assert.Equal(t, "JWT", parsedToken.Header["typ"])
			assert.NotEmpty(t, parsedToken.Header["kid"])
		})
	}
}

func TestTokenService_GenerateServiceToken_HeaderAndPayloadShape(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	service := &TokenService{
		TokenManager: token.NewTokenManager(keyManager, "https://tokensmith.openchami.dev", "default-cluster", "default-openchami", true),
		Config: Config{
			Issuer:      "https://tokensmith.openchami.dev",
			ClusterID:   "default-cluster",
			OpenCHAMIID: "default-openchami",
		},
		Issuer:      "https://tokensmith.openchami.dev",
		ClusterID:   "default-cluster",
		OpenCHAMIID: "default-openchami",
	}

	tokenValue, err := service.MintServiceToken(context.Background(), "dev-client", "smd", nil)
	require.NoError(t, err)

	parsedToken, _, err := jwt.NewParser().ParseUnverified(tokenValue, jwt.MapClaims{})
	require.NoError(t, err)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	kid, err := keyManager.GetKid()
	require.NoError(t, err)

	assert.Equal(t, service.TokenManager.GetSigningAlgorithm(), parsedToken.Header["alg"])
	assert.Equal(t, "JWT", parsedToken.Header["typ"])
	assert.Equal(t, kid, parsedToken.Header["kid"])

	assert.Equal(t, "https://tokensmith.openchami.dev", claims["iss"])
	assert.Equal(t, "dev-client", claims["sub"])
	assert.ElementsMatch(t, []interface{}{"smd"}, claims["aud"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["iat"])
	assert.NotNil(t, claims["nbf"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotEmpty(t, claims["nonce"])
	assert.Equal(t, "IAL2", claims["auth_level"])
	assert.Equal(t, float64(2), claims["auth_factors"])
	assert.ElementsMatch(t, []interface{}{"service", "certificate"}, claims["auth_methods"])
	assert.NotEmpty(t, claims["session_id"])
	assert.NotNil(t, claims["session_exp"])
	assert.ElementsMatch(t, []interface{}{"service_auth"}, claims["auth_events"])
	assert.Equal(t, "default-cluster", claims["cluster_id"])
	assert.Equal(t, "default-openchami", claims["openchami_id"])
	_, hasScope := claims["scope"]
	assert.False(t, hasScope)

	iat, ok := claims["iat"].(float64)
	require.True(t, ok)
	nbf, ok := claims["nbf"].(float64)
	require.True(t, ok)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	sessionExp, ok := claims["session_exp"].(float64)
	require.True(t, ok)

	assert.LessOrEqual(t, nbf, iat)
	assert.Greater(t, exp, iat)
	assert.GreaterOrEqual(t, sessionExp, exp)
}

func TestTokenService_ValidateToken(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Create key manager
	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	// Create test cases
	tests := []struct {
		name           string
		config         Config
		token          string
		expectError    bool
		validateClaims func(*testing.T, *token.TSClaims)
	}{
		{
			name: "valid token",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			expectError: false,
			validateClaims: func(t *testing.T, claims *token.TSClaims) {
				assert.Equal(t, "testuser", claims.Subject)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				// Verify NIST-compliant claims
				assert.Equal(t, "IAL2", claims.AuthLevel)
				assert.Equal(t, 2, claims.AuthFactors)
				assert.Equal(t, []string{"password", "mfa"}, claims.AuthMethods)
				assert.NotEmpty(t, claims.SessionID)
				assert.NotEmpty(t, claims.SessionExp)
				assert.Equal(t, []string{"login", "mfa"}, claims.AuthEvents)
			},
		},
		{
			name: "invalid token",
			config: Config{
				Issuer:           "test-issuer",
				ClusterID:        "test-cluster",
				OpenCHAMIID:      "test-openchami",
				OIDCIssuerURL:    "http://test-oidc",
				OIDCClientID:     "test-client",
				OIDCClientSecret: "test-secret",
			},
			token:       "invalid-token",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Create token service
			service := &TokenService{
				TokenManager: token.NewTokenManager(keyManager, tt.config.Issuer, tt.config.ClusterID, tt.config.OpenCHAMIID, true),
				Config:       tt.config,
				Issuer:       tt.config.Issuer,
				ClusterID:    tt.config.ClusterID,
				OpenCHAMIID:  tt.config.OpenCHAMIID,
			}

			// Generate a valid token for the valid token test case
			if !tt.expectError {
				claims := &token.TSClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    tt.config.Issuer,
						Subject:   "testuser",
						Audience:  []string{"smd", "bss", "cloud-init"},
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
					},
					ClusterID:   tt.config.ClusterID,
					OpenCHAMIID: tt.config.OpenCHAMIID,
					// Add NIST-compliant claims
					AuthLevel:   "IAL2",
					AuthFactors: 2,
					AuthMethods: []string{"password", "mfa"},
					SessionID:   "test-session-123",
					SessionExp:  time.Now().Add(24 * time.Hour).Unix(),
					AuthEvents:  []string{"login", "mfa"},
				}
				var err error
				tt.token, err = service.TokenManager.GenerateToken(claims)
				require.NoError(t, err)
				require.NotEmpty(t, tt.token)
			}

			// Validate token
			claims, err := service.ValidateToken(context.Background(), tt.token)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			tt.validateClaims(t, claims)
		})
	}
}

func TestTokenService_JWKSHandlerPublishesActiveSigningAlgorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	service, err := NewTokenService(keyManager, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-a",
		OpenCHAMIID: "openchami-a",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	service.JWKSHandler(w, req)
	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var jwks struct {
		Keys []struct {
			Algorithm string `json:"alg"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))
	require.Len(t, jwks.Keys, 1)
	assert.Equal(t, service.TokenManager.GetSigningAlgorithm(), jwks.Keys[0].Algorithm)
}

// TestOAuthTokenHandler_BootstrapExchangeThenRefresh is an end-to-end test of
// the RFC 8693 /oauth/token endpoint: opaque bootstrap token -> access+refresh,
// then refresh rotation (NIST SP 800-63-4 Section 6.2.2).
func TestOAuthTokenHandler_BootstrapExchangeThenRefresh(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	storePath := t.TempDir()
	var service *TokenService

	// --- Phase 1: Admin creates opaque bootstrap token ---
	bootstrapStore, err := NewBootstrapTokenStore(filepath.Join(storePath, "bootstrap-tokens"))
	require.NoError(t, err)

	opaqueToken := make([]byte, 32)
	_, err = rand.Read(opaqueToken)
	require.NoError(t, err)
	tokenHex := fmt.Sprintf("%x", opaqueToken)
	tokenHash := HashBootstrapToken(tokenHex)

	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "test-policy-1",
		Subject:    "svc-a",
		Audience:   "svc-b",
		Scopes:     []string{"read", "write"},
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	require.NoError(t, bootstrapStore.SavePolicy(policy))

	// Reload the service so it picks up the stored policy
	service, err = NewTokenService(keyManager, Config{
		Issuer:                    "http://tokensmith.test",
		ClusterID:                 "cluster-a",
		OpenCHAMIID:               "openchami-a",
		RFC8693BootstrapStorePath: filepath.Join(storePath, "bootstrap-tokens"),
		RFC8693RefreshStorePath:   filepath.Join(storePath, "refresh-tokens"),
	})
	require.NoError(t, err)

	// --- Phase 2: Exchange bootstrap token for access+refresh via /oauth/token ---
	form := fmt.Sprintf("grant_type=%s&subject_token=%s&subject_token_type=%s",
		GrantTypeTokenExchange, tokenHex, BootstrapTokenTypeRFC8693)
	bootstrapReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form))
	bootstrapReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bootstrapW := httptest.NewRecorder()

	service.OAuthTokenHandler(bootstrapW, bootstrapReq)
	require.Equal(t, http.StatusOK, bootstrapW.Result().StatusCode)

	var bootstrapOAuthResp OAuthTokenResponse
	require.NoError(t, json.NewDecoder(bootstrapW.Body).Decode(&bootstrapOAuthResp))
	require.NotEmpty(t, bootstrapOAuthResp.AccessToken)
	require.NotEmpty(t, bootstrapOAuthResp.RefreshToken)
	assert.Equal(t, "Bearer", bootstrapOAuthResp.TokenType)
	assert.Equal(t, 3600, bootstrapOAuthResp.ExpiresIn)
	assert.Greater(t, bootstrapOAuthResp.RefreshExpiresIn, 0)

	// Verify access token audience is the policy's audience
	claims, _, err := service.TokenManager.ParseToken(bootstrapOAuthResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "svc-a", claims.Subject)
	assert.Equal(t, []string{"svc-b"}, []string(claims.Audience))

	// --- Phase 3: Replay of bootstrap token must be rejected ---
	replayReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayW := httptest.NewRecorder()
	service.OAuthTokenHandler(replayW, replayReq)
	assert.Equal(t, http.StatusBadRequest, replayW.Result().StatusCode)

	// --- Phase 4: Use refresh token to rotate and obtain new access token ---
	refreshForm := fmt.Sprintf("grant_type=%s&refresh_token=%s",
		GrantTypeRefreshTokenRFC8693, bootstrapOAuthResp.RefreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshW := httptest.NewRecorder()

	service.OAuthTokenHandler(refreshW, refreshReq)
	require.Equal(t, http.StatusOK, refreshW.Result().StatusCode)

	var refreshOAuthResp OAuthTokenResponse
	require.NoError(t, json.NewDecoder(refreshW.Body).Decode(&refreshOAuthResp))
	require.NotEmpty(t, refreshOAuthResp.AccessToken)
	require.NotEmpty(t, refreshOAuthResp.RefreshToken)
	assert.NotEqual(t, bootstrapOAuthResp.RefreshToken, refreshOAuthResp.RefreshToken, "refresh token must be rotated")
	assert.Greater(t, refreshOAuthResp.RefreshExpiresIn, 0)

	// --- Phase 5: Replaying the old refresh token must be rejected (family revocation) ---
	replayRefreshReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm))
	replayRefreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRefreshW := httptest.NewRecorder()
	service.OAuthTokenHandler(replayRefreshW, replayRefreshReq)
	assert.Equal(t, http.StatusBadRequest, replayRefreshW.Result().StatusCode)
}
