package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openchami/tokensmith/pkg/jwt"
	"github.com/openchami/tokensmith/pkg/jwt/oidc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockProvider implements the OIDCProvider interface for testing
type MockProvider struct {
	introspectResponse *oidc.IntrospectionResponse
	metadataResponse   *oidc.ProviderMetadata
	jwks               jwk.Set
}

func (p *MockProvider) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	if p.introspectResponse == nil {
		return nil, fmt.Errorf("token introspection failed")
	}
	return p.introspectResponse, nil
}

func (p *MockProvider) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	if p.metadataResponse == nil {
		return &oidc.ProviderMetadata{
			Issuer:                "https://mock.example.com",
			IntrospectionEndpoint: "https://mock.example.com/introspect",
			JWKSURI:               "https://mock.example.com/jwks",
			ScopesSupported:       []string{"openid", "profile", "email"},
		}, nil
	}
	return p.metadataResponse, nil
}

func (p *MockProvider) SupportsLocalIntrospection() bool {
	return true
}

func (p *MockProvider) GetJWKS(ctx context.Context) (interface{}, error) {
	if p.jwks == nil {
		p.jwks = jwk.NewSet()
	}
	return p.jwks, nil
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

	// Create token service
	config := Config{
		ProviderType: ProviderTypeHydra,
		Issuer:       "https://openchami.example.com",
		GroupScopes: map[string][]string{
			"admin":    {"admin", "write", "read"},
			"operator": {"write", "read"},
			"viewer":   {"read"},
			"user":     {"read"},
		},
		ClusterID:   "test-cluster-id",
		OpenCHAMIID: "test-openchami-id",
	}

	// Create service with mock provider
	service := &TokenService{
		TokenManager: jwt.NewTokenManager(keyManager, config.Issuer, config.ClusterID, config.OpenCHAMIID),
		Config:       config,
		Issuer:       config.Issuer,
		GroupScopes:  config.GroupScopes,
		ClusterID:    config.ClusterID,
		OpenCHAMIID:  config.OpenCHAMIID,
		OIDCProvider: &MockProvider{},
	}

	t.Run("Token Exchange - Admin User", func(t *testing.T) {
		// Set up mock response
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "admin-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			TokenType: "Bearer",
			Claims: map[string]interface{}{
				"groups":         []interface{}{"admin"},
				"name":           "Admin User",
				"email":          "admin@example.com",
				"email_verified": true,
				"auth_level":     "IAL2",
				"auth_factors":   float64(2),
				"auth_methods":   []interface{}{"password", "mfa"},
				"session_id":     "test-session-123",
				"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
				"auth_events":    []interface{}{"login", "mfa"},
			},
		}

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
		assert.Equal(t, config.Issuer, claims.Issuer)
		assert.Equal(t, "admin-user", claims.Subject)
		assert.Equal(t, []string{"smd", "bss", "cloud-init"}, claims.Audience)
		assert.Equal(t, "Admin User", claims.Name)
		assert.Equal(t, "admin@example.com", claims.Email)
		assert.True(t, claims.EmailVerified)
		assert.Contains(t, claims.Scope, "admin")
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "read")
		// Verify NIST-compliant claims
		assert.Equal(t, "IAL2", claims.AuthLevel)
		assert.Equal(t, 2, claims.AuthFactors)
		assert.Equal(t, []string{"password", "mfa"}, claims.AuthMethods)
		assert.Equal(t, "test-session-123", claims.SessionID)
		assert.Equal(t, time.Now().Add(24*time.Hour).Unix(), claims.SessionExp)
		assert.Equal(t, []string{"login", "mfa"}, claims.AuthEvents)
	})

	t.Run("Token Exchange - Operator User", func(t *testing.T) {
		// Set up mock response
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "operator-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			TokenType: "Bearer",
			Claims: map[string]interface{}{
				"groups":         []interface{}{"operator"},
				"name":           "Operator User",
				"email":          "operator@example.com",
				"email_verified": true,
				"auth_level":     "IAL2",
				"auth_factors":   float64(2),
				"auth_methods":   []interface{}{"password", "mfa"},
				"session_id":     "test-session-456",
				"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
				"auth_events":    []interface{}{"login", "mfa"},
			},
		}

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
		assert.Equal(t, config.Issuer, claims.Issuer)
		assert.Equal(t, "operator-user", claims.Subject)
		assert.Equal(t, []string{"smd", "bss", "cloud-init"}, claims.Audience)
		assert.Equal(t, "Operator User", claims.Name)
		assert.Equal(t, "operator@example.com", claims.Email)
		assert.True(t, claims.EmailVerified)
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "read")
		assert.NotContains(t, claims.Scope, "admin")
		// Verify NIST-compliant claims
		assert.Equal(t, "IAL2", claims.AuthLevel)
		assert.Equal(t, 2, claims.AuthFactors)
		assert.Equal(t, []string{"password", "mfa"}, claims.AuthMethods)
		assert.Equal(t, "test-session-456", claims.SessionID)
		assert.Equal(t, time.Now().Add(24*time.Hour).Unix(), claims.SessionExp)
		assert.Equal(t, []string{"login", "mfa"}, claims.AuthEvents)
	})

	t.Run("Token Exchange - Multiple Groups", func(t *testing.T) {
		// Set up mock response
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "multi-group-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			TokenType: "Bearer",
			Claims: map[string]interface{}{
				"groups":         []interface{}{"admin", "operator"},
				"name":           "Multi Group User",
				"email":          "multi@example.com",
				"email_verified": true,
				"auth_level":     "IAL2",
				"auth_factors":   float64(2),
				"auth_methods":   []interface{}{"password", "mfa"},
				"session_id":     "test-session-789",
				"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
				"auth_events":    []interface{}{"login", "mfa"},
			},
		}

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
		assert.Equal(t, config.Issuer, claims.Issuer)
		assert.Equal(t, "multi-group-user", claims.Subject)
		assert.Equal(t, []string{"smd", "bss", "cloud-init"}, claims.Audience)
		assert.Equal(t, "Multi Group User", claims.Name)
		assert.Equal(t, "multi@example.com", claims.Email)
		assert.True(t, claims.EmailVerified)
		assert.Contains(t, claims.Scope, "admin")
		assert.Contains(t, claims.Scope, "write")
		assert.Contains(t, claims.Scope, "read")
		// Verify NIST-compliant claims
		assert.Equal(t, "IAL2", claims.AuthLevel)
		assert.Equal(t, 2, claims.AuthFactors)
		assert.Equal(t, []string{"password", "mfa"}, claims.AuthMethods)
		assert.Equal(t, "test-session-789", claims.SessionID)
		assert.Equal(t, time.Now().Add(24*time.Hour).Unix(), claims.SessionExp)
		assert.Equal(t, []string{"login", "mfa"}, claims.AuthEvents)
	})

	t.Run("Token Exchange - Invalid Token", func(t *testing.T) {
		// Set up mock response for inactive token
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    false,
			Username:  "testuser",
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
			IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
			TokenType: "Bearer",
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "invalid-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token is not active")
	})

	t.Run("Token Exchange - Missing Groups", func(t *testing.T) {
		// Set up mock response without groups
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "no-groups-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			TokenType: "Bearer",
			Claims: map[string]interface{}{
				"name":           "No Groups User",
				"email":          "nogroups@example.com",
				"email_verified": true,
				"auth_level":     "IAL2",
				"auth_factors":   float64(2),
				"auth_methods":   []interface{}{"password", "mfa"},
				"session_id":     "test-session-123",
				"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
				"auth_events":    []interface{}{"login", "mfa"},
			},
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "no-groups-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "no groups found in token")
	})

	t.Run("Token Exchange - Invalid Group Type", func(t *testing.T) {
		// Set up mock response with invalid group type
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "invalid-group-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			TokenType: "Bearer",
			Claims: map[string]interface{}{
				"groups":         []interface{}{123}, // Invalid group type
				"name":           "Invalid Group User",
				"email":          "invalid@example.com",
				"email_verified": true,
				"auth_level":     "IAL2",
				"auth_factors":   float64(2),
				"auth_methods":   []interface{}{"password", "mfa"},
				"session_id":     "test-session-123",
				"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
				"auth_events":    []interface{}{"login", "mfa"},
			},
		}

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "invalid-group-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "no valid scopes found for groups")
	})

	t.Run("Update Group Scopes", func(t *testing.T) {
		// Update group scopes
		newScopes := map[string][]string{
			"admin":    {"admin", "write", "read", "new-scope"},
			"operator": {"write", "read"},
		}
		service.UpdateGroupScopes(newScopes)

		// Set up mock response
		service.OIDCProvider.(*MockProvider).introspectResponse = &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "admin-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			TokenType: "Bearer",
			Claims: map[string]interface{}{
				"groups":         []interface{}{"admin"},
				"name":           "Admin User",
				"email":          "admin@example.com",
				"email_verified": true,
				"auth_level":     "IAL2",
				"auth_factors":   float64(2),
				"auth_methods":   []interface{}{"password", "mfa"},
				"session_id":     "test-session-123",
				"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
				"auth_events":    []interface{}{"login", "mfa"},
			},
		}

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
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Token Exchange - Provider Error", func(t *testing.T) {
		// Set up mock provider to return an error
		mockProvider := &MockProvider{}
		mockProvider.introspectResponse = nil // This will cause the mock to return a default response
		service.OIDCProvider = mockProvider

		// Exchange token
		token, err := service.ExchangeToken(context.Background(), "test-token")
		require.Error(t, err)
		require.Empty(t, token)
		assert.Contains(t, err.Error(), "token introspection failed")
	})
}

func TestTokenService_ExchangeToken(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Create key manager
	keyManager := jwt.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	// Create test cases
	tests := []struct {
		name           string
		config         Config
		introspectResp *oidc.IntrospectionResponse
		expectError    bool
		validateClaims func(*testing.T, *jwt.Claims)
	}{
		{
			name: "valid token",
			config: Config{
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
				GroupScopes: map[string][]string{
					"admin": {"admin", "write", "read"},
				},
			},
			introspectResp: &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				TokenType: "Bearer",
				Claims: map[string]interface{}{
					"groups":         []interface{}{"admin"},
					"name":           "Test User",
					"email":          "test@example.com",
					"email_verified": true,
					"auth_level":     "IAL2",
					"auth_factors":   float64(2),
					"auth_methods":   []interface{}{"password", "mfa"},
					"session_id":     "test-session-123",
					"session_exp":    float64(time.Now().Add(24 * time.Hour).Unix()),
					"auth_events":    []interface{}{"login", "mfa"},
				},
			},
			expectError: false,
			validateClaims: func(t *testing.T, claims *jwt.Claims) {
				assert.Equal(t, "testuser", claims.Subject)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "Test User", claims.Name)
				assert.Equal(t, "test@example.com", claims.Email)
				assert.True(t, claims.EmailVerified)
				assert.Contains(t, claims.Scope, "admin")
				assert.Contains(t, claims.Scope, "write")
				assert.Contains(t, claims.Scope, "read")
				// Verify NIST-compliant claims
				assert.Equal(t, "IAL2", claims.AuthLevel)
				assert.Equal(t, 2, claims.AuthFactors)
				assert.Equal(t, []string{"password", "mfa"}, claims.AuthMethods)
				assert.Equal(t, "test-session-123", claims.SessionID)
				assert.Equal(t, time.Now().Add(24*time.Hour).Unix(), claims.SessionExp)
				assert.Equal(t, []string{"login", "mfa"}, claims.AuthEvents)
			},
		},
		{
			name: "inactive token",
			config: Config{
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
			},
			introspectResp: &oidc.IntrospectionResponse{
				Active:    false,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(-time.Hour).Unix(),
				IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
				TokenType: "Bearer",
			},
			expectError: true,
		},
		{
			name: "token with no scopes",
			config: Config{
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
			},
			introspectResp: &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				TokenType: "Bearer",
				Claims: map[string]interface{}{
					"groups": []interface{}{"admin"},
				},
			},
			expectError: true,
		},
		{
			name: "token without NIST-compliant claims",
			config: Config{
				ProviderType: ProviderTypeHydra,
				Issuer:       "test-issuer",
				ClusterID:    "test-cluster",
				OpenCHAMIID:  "test-openchami",
				GroupScopes: map[string][]string{
					"admin": {"admin", "write", "read"},
				},
			},
			introspectResp: &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				TokenType: "Bearer",
				Claims: map[string]interface{}{
					"groups":         []interface{}{"admin"},
					"name":           "Test User",
					"email":          "test@example.com",
					"email_verified": true,
					// Missing NIST-compliant claims:
					// - auth_level
					// - auth_factors
					// - auth_methods
					// - session_id
					// - session_exp
					// - auth_events
				},
			},
			expectError: true,
			validateClaims: func(t *testing.T, claims *jwt.Claims) {
				// This should not be called since the token should fail validation
				t.Fatal("validateClaims should not be called for invalid token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create token service with mock provider
			service := &TokenService{
				TokenManager: jwt.NewTokenManager(keyManager, tt.config.Issuer, tt.config.ClusterID, tt.config.OpenCHAMIID),
				Config:       tt.config,
				Issuer:       tt.config.Issuer,
				ClusterID:    tt.config.ClusterID,
				OpenCHAMIID:  tt.config.OpenCHAMIID,
				GroupScopes:  tt.config.GroupScopes,
				OIDCProvider: &MockProvider{
					introspectResponse: tt.introspectResp,
				},
			}

			// Exchange token
			token, err := service.ExchangeToken(context.Background(), "test-token")
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			// Parse and verify token
			claims, _, err := service.TokenManager.ParseToken(token)
			require.NoError(t, err)
			require.NotNil(t, claims)
			tt.validateClaims(t, claims)
		})
	}
}

func TestTokenService_GenerateServiceToken(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	// Create key manager
	keyManager := jwt.NewKeyManager()
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
		validateClaims func(*testing.T, *jwt.Claims)
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
			validateClaims: func(t *testing.T, claims *jwt.Claims) {
				assert.Equal(t, "service1", claims.Subject)
				assert.Equal(t, "service2", claims.Audience[0])
				assert.Equal(t, []string{"read", "write"}, claims.Scope)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "test-issuer", claims.Issuer)
				assert.NotEmpty(t, claims.ExpirationTime)
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
			validateClaims: func(t *testing.T, claims *jwt.Claims) {
				assert.Equal(t, "service1", claims.Subject)
				assert.Equal(t, "service2", claims.Audience[0])
				assert.Empty(t, claims.Scope)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "test-issuer", claims.Issuer)
				assert.NotEmpty(t, claims.ExpirationTime)
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
			validateClaims: func(t *testing.T, claims *jwt.Claims) {
				assert.Equal(t, "service1", claims.Subject)
				assert.Equal(t, "service2", claims.Audience[0])
				assert.Nil(t, claims.Scope)
				assert.Equal(t, "test-cluster", claims.ClusterID)
				assert.Equal(t, "test-openchami", claims.OpenCHAMIID)
				assert.Equal(t, "test-issuer", claims.Issuer)
				assert.NotEmpty(t, claims.ExpirationTime)
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
				TokenManager: jwt.NewTokenManager(keyManager, tt.config.Issuer, tt.config.ClusterID, tt.config.OpenCHAMIID),
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
	keyManager := jwt.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	// Create test cases
	tests := []struct {
		name           string
		config         Config
		token          string
		expectError    bool
		validateClaims func(*testing.T, *jwt.Claims)
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
			validateClaims: func(t *testing.T, claims *jwt.Claims) {
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
				TokenManager: jwt.NewTokenManager(keyManager, tt.config.Issuer, tt.config.ClusterID, tt.config.OpenCHAMIID),
				Config:       tt.config,
				Issuer:       tt.config.Issuer,
				ClusterID:    tt.config.ClusterID,
				OpenCHAMIID:  tt.config.OpenCHAMIID,
			}

			// Generate a valid token for the valid token test case
			if !tt.expectError {
				claims := &jwt.Claims{
					Issuer:         tt.config.Issuer,
					Subject:        "testuser",
					Audience:       []string{"smd", "bss", "cloud-init"},
					ExpirationTime: time.Now().Add(time.Hour).Unix(),
					IssuedAt:       time.Now().Unix(),
					ClusterID:      tt.config.ClusterID,
					OpenCHAMIID:    tt.config.OpenCHAMIID,
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
