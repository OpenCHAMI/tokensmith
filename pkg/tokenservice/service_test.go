package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/oidc/mock"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenService(t *testing.T) {
	// Create a mock provider using the existing mock implementation
	mockProvider := mock.NewProvider()
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
	mockProvider.SupportsLocalFunc = func() bool {
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
		Issuer:      "test-issuer",
		ClusterID:   "test-cluster-id",
		OpenCHAMIID: "test-openchami-id",
		GroupScopes: map[string][]string{
			"admin":    {"read", "write", "admin"},
			"operator": {"read", "write"},
			"user":     {"read"},
		},
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
		service.OIDCProvider.(*mock.Provider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
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
		service.OIDCProvider.(*mock.Provider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
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
		service.OIDCProvider.(*mock.Provider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
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
		service.OIDCProvider.(*mock.Provider).IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
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
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
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
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
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
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
			},
			serviceID:     "",
			targetService: "service2",
			scopes:        []string{"read", "write"},
			expectError:   true,
		},
		{
			name: "empty target service",
			config: Config{
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
			},
			serviceID:     "service1",
			targetService: "",
			scopes:        []string{"read", "write"},
			expectError:   true,
		},
		{
			name: "nil scopes",
			config: Config{
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
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
			token, err := service.GenerateServiceToken(context.Background(), tt.serviceID, tt.targetService, tt.scopes)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Parse and validate claims
			claims, _, err := service.TokenManager.ParseToken(token)
			assert.NoError(t, err)
			tt.validateClaims(t, claims)
		})
	}
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
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
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
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
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
