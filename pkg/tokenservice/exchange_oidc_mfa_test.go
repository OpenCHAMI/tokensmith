// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ExchangeToken_OIDCMFAClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	tokenManager := token.NewTokenManager(keyManager, "test-issuer", "test-cluster", "test-openchami", true)

	t.Run("Extract AMR from OIDC introspection", func(t *testing.T) {
		mockProvider := oidc.NewMockProvider()
		mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			now := time.Now()
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "mfa-user",
				ExpiresAt: now.Add(time.Hour).Unix(),
				IssuedAt:  now.Unix(),
				Claims: map[string]interface{}{
					"sub":       "mfa-user",
					"aud":       []interface{}{"test-audience"},
					"amr":       []interface{}{"pwd", "otp"},
					"auth_time": float64(now.Unix()),
				},
				TokenType: "Bearer",
			}, nil
		}

		service := &TokenService{
			TokenManager: tokenManager,
			Issuer:       "test-issuer",
			ClusterID:    "test-cluster",
			OpenCHAMIID:  "test-openchami",
			OIDCProvider: mockProvider,
		}

		jwtToken, err := service.ExchangeToken(context.Background(), "test-token")
		require.NoError(t, err)
		require.NotEmpty(t, jwtToken)

		claims, _, err := tokenManager.ParseToken(jwtToken)
		require.NoError(t, err)
		assert.Equal(t, []string{"pwd", "otp"}, claims.AMR)
		assert.Equal(t, 2, claims.AuthFactors, "Should derive 2 factors from pwd (knowledge) + otp (possession)")
		assert.Equal(t, []string{"pwd", "otp"}, claims.AuthMethods, "Should map AMR to AuthMethods for backward compatibility")
	})

	t.Run("Extract ACR from OIDC introspection", func(t *testing.T) {
		mockProvider := oidc.NewMockProvider()
		mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			now := time.Now()
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "acr-user",
				ExpiresAt: now.Add(time.Hour).Unix(),
				IssuedAt:  now.Unix(),
				Claims: map[string]interface{}{
					"sub": "acr-user",
					"aud": []interface{}{"test-audience"},
					"acr": "urn:mfa:required",
					"amr": []interface{}{"pwd", "fido2"},
				},
				TokenType: "Bearer",
			}, nil
		}

		service := &TokenService{
			TokenManager: tokenManager,
			Issuer:       "test-issuer",
			ClusterID:    "test-cluster",
			OpenCHAMIID:  "test-openchami",
			OIDCProvider: mockProvider,
		}

		jwtToken, err := service.ExchangeToken(context.Background(), "test-token")
		require.NoError(t, err)

		claims, _, err := tokenManager.ParseToken(jwtToken)
		require.NoError(t, err)
		assert.Equal(t, "urn:mfa:required", claims.ACR)
	})

	t.Run("Extract auth_time from OIDC introspection", func(t *testing.T) {
		mockProvider := oidc.NewMockProvider()
		authTime := time.Now().Add(-30 * time.Minute).Unix()
		mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			now := time.Now()
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "auth-time-user",
				ExpiresAt: now.Add(time.Hour).Unix(),
				IssuedAt:  now.Unix(),
				Claims: map[string]interface{}{
					"sub":       "auth-time-user",
					"aud":       []interface{}{"test-audience"},
					"auth_time": float64(authTime),
					"amr":       []interface{}{"pwd"},
				},
				TokenType: "Bearer",
			}, nil
		}

		service := &TokenService{
			TokenManager: tokenManager,
			Issuer:       "test-issuer",
			ClusterID:    "test-cluster",
			OpenCHAMIID:  "test-openchami",
			OIDCProvider: mockProvider,
		}

		jwtToken, err := service.ExchangeToken(context.Background(), "test-token")
		require.NoError(t, err)

		claims, _, err := tokenManager.ParseToken(jwtToken)
		require.NoError(t, err)
		assert.Equal(t, authTime, claims.AuthTime)
	})

	t.Run("Derive AuthFactors from AMR - multiple factor categories", func(t *testing.T) {
		mockProvider := oidc.NewMockProvider()
		mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			now := time.Now()
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "multi-factor-user",
				ExpiresAt: now.Add(time.Hour).Unix(),
				IssuedAt:  now.Unix(),
				Claims: map[string]interface{}{
					"sub": "multi-factor-user",
					"aud": []interface{}{"test-audience"},
					"amr": []interface{}{"pwd", "sms", "fido2"},
				},
				TokenType: "Bearer",
			}, nil
		}

		service := &TokenService{
			TokenManager: tokenManager,
			Issuer:       "test-issuer",
			ClusterID:    "test-cluster",
			OpenCHAMIID:  "test-openchami",
			OIDCProvider: mockProvider,
		}

		jwtToken, err := service.ExchangeToken(context.Background(), "test-token")
		require.NoError(t, err)

		claims, _, err := tokenManager.ParseToken(jwtToken)
		require.NoError(t, err)
		assert.Equal(t, 3, claims.AuthFactors, "pwd=knowledge, sms=possession, fido2=inherence = 3 factors")
		assert.Equal(t, []string{"pwd", "sms", "fido2"}, claims.AMR)
	})

	t.Run("Backward compatibility - custom NIST claims still work", func(t *testing.T) {
		mockProvider := oidc.NewMockProvider()
		mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			now := time.Now()
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "nist-user",
				ExpiresAt: now.Add(time.Hour).Unix(),
				IssuedAt:  now.Unix(),
				Claims: map[string]interface{}{
					"sub":          "nist-user",
					"aud":          []interface{}{"test-audience"},
					"auth_level":   "IAL2",
					"auth_factors": float64(2),
					"auth_methods": []interface{}{"password", "webauthn"},
					"amr":          []interface{}{"pwd", "fido2"},
					"acr":          "urn:mfa:required",
					"auth_time":    float64(now.Unix()),
				},
				TokenType: "Bearer",
			}, nil
		}

		service := &TokenService{
			TokenManager: tokenManager,
			Issuer:       "test-issuer",
			ClusterID:    "test-cluster",
			OpenCHAMIID:  "test-openchami",
			OIDCProvider: mockProvider,
		}

		jwtToken, err := service.ExchangeToken(context.Background(), "test-token")
		require.NoError(t, err)

		claims, _, err := tokenManager.ParseToken(jwtToken)
		require.NoError(t, err)

		assert.Equal(t, "IAL2", claims.AuthLevel, "Custom auth_level preserved")
		assert.Equal(t, 2, claims.AuthFactors, "Custom auth_factors takes precedence")
		assert.Equal(t, []string{"password", "webauthn"}, claims.AuthMethods, "Custom auth_methods takes precedence")

		assert.Equal(t, []string{"pwd", "fido2"}, claims.AMR, "OIDC AMR also populated")
		assert.Equal(t, "urn:mfa:required", claims.ACR, "OIDC ACR also populated")
		assert.NotZero(t, claims.AuthTime, "OIDC auth_time also populated")
	})

	t.Run("OIDC-only claims work without custom NIST claims", func(t *testing.T) {
		mockProvider := oidc.NewMockProvider()
		mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
			now := time.Now()
			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "oidc-only-user",
				ExpiresAt: now.Add(time.Hour).Unix(),
				IssuedAt:  now.Unix(),
				Claims: map[string]interface{}{
					"sub":       "oidc-only-user",
					"aud":       []interface{}{"test-audience"},
					"amr":       []interface{}{"pwd", "otp"},
					"acr":       "AAL2",
					"auth_time": float64(now.Unix()),
				},
				TokenType: "Bearer",
			}, nil
		}

		service := &TokenService{
			TokenManager: tokenManager,
			Issuer:       "test-issuer",
			ClusterID:    "test-cluster",
			OpenCHAMIID:  "test-openchami",
			OIDCProvider: mockProvider,
		}

		jwtToken, err := service.ExchangeToken(context.Background(), "test-token")
		require.NoError(t, err, "Should succeed with OIDC-only claims")

		claims, _, err := tokenManager.ParseToken(jwtToken)
		require.NoError(t, err)

		assert.Equal(t, []string{"pwd", "otp"}, claims.AMR)
		assert.Equal(t, "AAL2", claims.ACR)
		assert.NotZero(t, claims.AuthTime)
		assert.Equal(t, 2, claims.AuthFactors, "Derived from AMR")
		assert.Equal(t, []string{"pwd", "otp"}, claims.AuthMethods, "Mapped from AMR")
		assert.Empty(t, claims.AuthLevel, "Not provided, not required")
	})
}

func Test_deriveAuthFactorsFromAMR(t *testing.T) {
	tests := []struct {
		name     string
		amr      []string
		expected int
	}{
		{
			name:     "Single factor - password only",
			amr:      []string{"pwd"},
			expected: 1,
		},
		{
			name:     "Two factors - password + OTP",
			amr:      []string{"pwd", "otp"},
			expected: 2,
		},
		{
			name:     "Three factors - knowledge + possession + inherence",
			amr:      []string{"pwd", "sms", "fido2"},
			expected: 3,
		},
		{
			name:     "Multiple methods in same category count as one",
			amr:      []string{"pwd", "pin", "kba"},
			expected: 1,
		},
		{
			name:     "FIDO2 alone",
			amr:      []string{"fido2"},
			expected: 1,
		},
		{
			name:     "Biometric + password",
			amr:      []string{"bio", "pwd"},
			expected: 2,
		},
		{
			name:     "Unknown method",
			amr:      []string{"custom-method"},
			expected: 1,
		},
		{
			name:     "Empty AMR",
			amr:      []string{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveAuthFactorsFromAMR(tt.amr)
			assert.Equal(t, tt.expected, result)
		})
	}
}
