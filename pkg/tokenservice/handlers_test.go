// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoutes_OAuthTokenUsesRFC8693Handler(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	router := svc.newRouter(zerolog.New(io.Discard))
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	router.ServeHTTP(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)

	var oauthErr OAuthErrorResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&oauthErr))
	assert.Equal(t, "invalid_request", oauthErr.Error)
	assert.Contains(t, oauthErr.ErrorDescription, "grant_type")
}

func TestTokenExchangeHandler_MethodNotAllowed(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	req := httptest.NewRequest(http.MethodGet, "/oauth/exchange", nil)
	resp := httptest.NewRecorder()

	svc.TokenExchangeHandler(resp, req)

	require.Equal(t, http.StatusMethodNotAllowed, resp.Code)
}

func TestTokenExchangeHandler_InvalidJSONReturnsBadRequest(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	req := httptest.NewRequest(http.MethodPost, "/oauth/exchange", strings.NewReader("{invalid"))
	req.Header.Set("Authorization", "Bearer opaque-id-token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	svc.TokenExchangeHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid request body")
}

func TestTokenExchangeHandler_AcceptsCaseInsensitiveBearer(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
		GroupScopes: map[string][]string{
			"viewer": {"read"},
		},
	})

	mockProvider := oidc.NewMockProvider()
	mockProvider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		now := time.Now()
		return &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "case-user",
			ExpiresAt: now.Add(time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			Claims: map[string]interface{}{
				"aud":          []interface{}{"svc-target"},
				"groups":       []interface{}{"viewer"},
				"auth_level":   "IAL2",
				"auth_factors": float64(2),
				"auth_methods": []interface{}{"password", "mfa"},
				"session_id":   "sid-case-user",
				"session_exp":  float64(now.Add(time.Hour).Unix()),
				"auth_events":  []interface{}{"login"},
			},
			TokenType: "Bearer",
		}, nil
	}
	svc.OIDCProvider = mockProvider

	req := httptest.NewRequest(http.MethodPost, "/oauth/exchange", strings.NewReader(`{"scope":["read"],"target_service":"svc-target"}`))
	req.Header.Set("Authorization", "bearer opaque-id-token")
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	svc.TokenExchangeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var tokenResp map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tokenResp))
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.Equal(t, "Bearer", tokenResp["token_type"])
}

func TestTokenExchangeHandler_LogsMissingClaimCategoryWithoutToken(t *testing.T) {
	const tokenValue = "secret-bearer-token-never-log"
	var logs bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previousLogger })

	svc := newTestTokenService(t, Config{
		Issuer:          "http://tokensmith.test",
		ClusterID:       "cluster-test",
		OpenCHAMIID:     "openchami-test",
		OIDCClaimPolicy: OIDCClaimPolicyEnriched,
	})
	provider := oidc.NewMockProvider()
	provider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		assert.Equal(t, tokenValue, token)
		return &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "admin-user",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Claims: map[string]interface{}{
				"sub": "admin-user",
				"aud": []interface{}{"svc-target"},
			},
			TokenType: "Bearer",
		}, nil
	}
	svc.OIDCProvider = provider

	req := httptest.NewRequest(http.MethodPost, "/oauth/exchange", strings.NewReader(`{"scope":["read"],"target_service":"svc-target"}`))
	req.Header.Set("Authorization", "Bearer "+tokenValue)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	svc.newRouter(zerolog.New(io.Discard)).ServeHTTP(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, logs.String(), "token_exchange_failed")
	assert.Contains(t, logs.String(), "missing_claim")
	assert.Contains(t, logs.String(), "auth_level")
	assert.NotContains(t, logs.String(), tokenValue)
}

func TestTokenExchangeMiddleware_LogsUpstreamCategoryWithoutToken(t *testing.T) {
	const tokenValue = "secret-upstream-token-never-log"
	var logs bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previousLogger })

	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})
	provider := oidc.NewMockProvider()
	provider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		assert.Equal(t, tokenValue, token)
		return nil, fmt.Errorf("provider failed: %w", oidc.ErrUpstreamUnavailable)
	}
	svc.OIDCProvider = provider

	req := httptest.NewRequest(http.MethodPost, "/oauth/exchange", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tokenValue)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	svc.newRouter(zerolog.New(io.Discard)).ServeHTTP(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, logs.String(), "token_exchange_failed")
	assert.Contains(t, logs.String(), "upstream_unavailable")
	assert.NotContains(t, logs.String(), tokenValue)
}

func TestTokenExchangeMiddleware_LogsProviderMetadataCategory(t *testing.T) {
	const tokenValue = "secret-metadata-token-never-log"
	var logs bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previousLogger })

	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})
	provider := oidc.NewMockProvider()
	provider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		assert.Equal(t, tokenValue, token)
		return nil, &oidc.ProviderError{
			Operation: "validate provider metadata",
			Kind:      oidc.ErrProviderMetadata,
			Cause:     errors.New("missing required field: introspection_endpoint or token_introspection_endpoint"),
		}
	}
	svc.OIDCProvider = provider

	req := httptest.NewRequest(http.MethodPost, "/oauth/exchange", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tokenValue)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	svc.newRouter(zerolog.New(io.Discard)).ServeHTTP(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, logs.String(), "token_exchange_failed")
	assert.Contains(t, logs.String(), "provider_metadata")
	assert.Contains(t, logs.String(), "provider_operation")
	assert.Contains(t, logs.String(), "token_introspection_endpoint")
	assert.NotContains(t, logs.String(), tokenValue)
}

func TestTokenExchangeHandler_LogsGeneratedClaimValidationCategory(t *testing.T) {
	const tokenValue = "secret-invalid-generated-claims-token-never-log"
	var logs bytes.Buffer
	previousLogger := log.Logger
	log.Logger = zerolog.New(&logs)
	t.Cleanup(func() { log.Logger = previousLogger })

	now := time.Now()
	svc := newTestTokenService(t, Config{
		Issuer:          "http://tokensmith.test",
		ClusterID:       "cluster-test",
		OpenCHAMIID:     "openchami-test",
		OIDCClaimPolicy: OIDCClaimPolicyCSMKeycloak,
		GroupScopes: map[string][]string{
			"admin": {"read", "write", "admin"},
		},
	})
	provider := oidc.NewMockProvider()
	provider.IntrospectTokenFunc = func(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
		assert.Equal(t, tokenValue, token)
		return &oidc.IntrospectionResponse{
			Active:    true,
			Username:  "testuser",
			ExpiresAt: now.Add(48 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			Claims: map[string]interface{}{
				"sub":         "testuser",
				"groups":      []interface{}{"admin"},
				"acr":         "0",
				"sid":         "session-1",
				"exp":         float64(now.Add(48 * time.Hour).Unix()),
				"auth_events": []interface{}{"login"},
			},
			TokenType: "Bearer",
		}, nil
	}
	svc.OIDCProvider = provider

	req := httptest.NewRequest(http.MethodPost, "/oauth/exchange", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tokenValue)
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	svc.newRouter(zerolog.New(io.Discard)).ServeHTTP(resp, req)

	require.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Contains(t, logs.String(), "token_exchange_failed")
	assert.Contains(t, logs.String(), "generated_claim_validation")
	assert.Contains(t, logs.String(), "generate_token")
	assert.NotContains(t, logs.String(), tokenValue)
}
