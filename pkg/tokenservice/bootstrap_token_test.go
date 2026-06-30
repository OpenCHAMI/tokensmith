// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBootstrapTokenHandler_ConsumedTokenReturnsInvalidGrant verifies one-time-use enforcement.
// Per NIST SP 800-63, bootstrap tokens MUST be single-use.
func TestBootstrapTokenHandler_ConsumedTokenReturnsInvalidGrant(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	bootstrapToken, err := svc.generateOpaqueToken(32)
	require.NoError(t, err)
	tokenHash := HashBootstrapToken(bootstrapToken)

	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-consumed-test",
		Subject:    "boot-service",
		Audience:   "smd",
		Scopes:     []string{"read", "write"},
		TokenHash:  tokenHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	require.NoError(t, svc.bootstrapTokenStore.UpdatePolicy(policy))

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	form.Set("subject_token", bootstrapToken)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var firstResp OAuthTokenResponse
	require.NoError(t, parseJSON(resp.Body, &firstResp))
	require.NotEmpty(t, firstResp.AccessToken)
	require.NotEmpty(t, firstResp.RefreshToken)

	form = url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	form.Set("subject_token", bootstrapToken)

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "invalid or has already been used")

	reloadedPolicy, err := svc.bootstrapTokenStore.GetPolicy(tokenHash)
	require.NoError(t, err)
	assert.True(t, reloadedPolicy.IsConsumed(), "Bootstrap token MUST remain consumed")
	require.NotNil(t, reloadedPolicy.ConsumedAt, "ConsumedAt timestamp MUST be set")
}

// TestBootstrapTokenHandler_ExpiredPolicyReturnsInvalidGrant verifies policy expiration enforcement.
func TestBootstrapTokenHandler_ExpiredPolicyReturnsInvalidGrant(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	bootstrapToken, err := svc.generateOpaqueToken(32)
	require.NoError(t, err)
	tokenHash := HashBootstrapToken(bootstrapToken)

	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-expired-test",
		Subject:    "boot-service",
		Audience:   "smd",
		Scopes:     []string{"read"},
		TokenHash:  tokenHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now.Add(-2 * time.Hour),
		ExpiresAt:  now.Add(-1 * time.Hour),
	}
	require.NoError(t, svc.bootstrapTokenStore.UpdatePolicy(policy))

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	form.Set("subject_token", bootstrapToken)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "invalid or has already been used")
}

// TestBootstrapTokenHandler_ValidatesAudience verifies audience claim enforcement.
// NOTE: Current implementation does NOT validate audience in bootstrap exchange.
// This test documents the expected behavior for future implementation.
func TestBootstrapTokenHandler_ValidatesAudience(t *testing.T) {
	t.Skip("TODO: Audience validation not currently implemented in bootstrap token handler")

	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	bootstrapToken, err := svc.generateOpaqueToken(32)
	require.NoError(t, err)
	tokenHash := HashBootstrapToken(bootstrapToken)

	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-audience-test",
		Subject:    "boot-service",
		Audience:   "smd",
		Scopes:     []string{"read"},
		TokenHash:  tokenHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	require.NoError(t, svc.bootstrapTokenStore.UpdatePolicy(policy))

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	form.Set("subject_token", bootstrapToken)
	form.Set("audience", "wrong-service")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_request", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "audience")
}

// TestBootstrapTokenHandler_InvalidTokenReturnsInvalidGrant verifies rejection of unknown tokens.
func TestBootstrapTokenHandler_InvalidTokenReturnsInvalidGrant(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	form.Set("subject_token", "completely-invalid-bootstrap-token-12345")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)
}

// TestBootstrapTokenHandler_MissingSubjectTokenReturnsInvalidRequest verifies parameter validation.
func TestBootstrapTokenHandler_MissingSubjectTokenReturnsInvalidRequest(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_request", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "subject_token")
}

// TestBootstrapTokenHandler_InvalidSubjectTokenTypeReturnsInvalidRequest verifies token type validation.
func TestBootstrapTokenHandler_InvalidSubjectTokenTypeReturnsInvalidRequest(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	form.Set("subject_token", "some-jwt-token")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_request", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "subject_token_type")
}
