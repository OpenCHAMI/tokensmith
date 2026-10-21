// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
				Issuer: "test-issuer", ClusterID: "test-cluster", OpenCHAMIID: "test-openchami", OIDCIssuerURL: "http://test-oidc", OIDCClientID: "test-client", OIDCClientSecret: "test-secret",
			},
			serviceID: "service1", targetService: "service2", scopes: []string{"read", "write"}, expectError: false,
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
				Issuer: "test-issuer", ClusterID: "test-cluster", OpenCHAMIID: "test-openchami", OIDCIssuerURL: "http://test-oidc", OIDCClientID: "test-client", OIDCClientSecret: "test-secret",
			},
			serviceID: "service1", targetService: "service2", scopes: []string{}, expectError: false,
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
				Issuer: "test-issuer", ClusterID: "test-cluster", OpenCHAMIID: "test-openchami", OIDCIssuerURL: "http://test-oidc", OIDCClientID: "test-client", OIDCClientSecret: "test-secret",
			},
			serviceID: "", targetService: "service2", scopes: []string{"read", "write"}, expectError: true,
		},
		{
			name: "empty target service",
			config: Config{
				Issuer: "test-issuer", ClusterID: "test-cluster", OpenCHAMIID: "test-openchami", OIDCIssuerURL: "http://test-oidc", OIDCClientID: "test-client", OIDCClientSecret: "test-secret",
			},
			serviceID: "service1", targetService: "", scopes: []string{"read", "write"}, expectError: true,
		},
		{
			name: "nil scopes",
			config: Config{
				Issuer: "test-issuer", ClusterID: "test-cluster", OpenCHAMIID: "test-openchami", OIDCIssuerURL: "http://test-oidc", OIDCClientID: "test-client", OIDCClientSecret: "test-secret",
			},
			serviceID: "service1", targetService: "service2", scopes: nil, expectError: false,
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
