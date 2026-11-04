// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
					SessionExp:  time.Now().Add(time.Hour).Unix(),
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
