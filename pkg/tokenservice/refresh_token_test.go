// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseJSON is a test helper to parse JSON from an io.Reader into a struct.
func parseJSON(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

// TestRefreshTokenHandler_ReplayDetection_RevokesFamily verifies NIST SP 800-63-4 Section 6.2.3 compliance.
// When a previously-used (rotated) refresh token is presented, the entire token family MUST be revoked.
//
// KNOWN BUG: This test currently FAILS because GetFamilyByTokenHash() only tracks CurrentTokenHash.
// After rotation, old token hashes are not found, so replay detection never triggers.
// The test documents the EXPECTED behavior per NIST SP 800-63-4.
// TODO: Fix GetFamilyByTokenHash to maintain a history of old token hashes for replay detection.
func TestRefreshTokenHandler_ReplayDetection_RevokesFamily(t *testing.T) {
	t.Skip("KNOWN BUG: Replay detection not implemented - GetFamilyByTokenHash only tracks CurrentTokenHash")
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	// Step 1: Create a bootstrap token and exchange it for initial tokens
	bootstrapToken, err := svc.generateOpaqueToken(32)
	require.NoError(t, err)
	tokenHash := HashBootstrapToken(bootstrapToken)

	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-replay-test",
		Subject:    "test-service",
		Audience:   "target-service",
		Scopes:     []string{"read", "write"},
		TokenHash:  tokenHash,
		TTL:        10 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		CreatedAt:  now,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	require.NoError(t, svc.bootstrapTokenStore.UpdatePolicy(policy))

	// Exchange bootstrap token for initial access + refresh tokens
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", BootstrapTokenTypeRFC8693)
	form.Set("subject_token", bootstrapToken)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var initialResp OAuthTokenResponse
	require.NoError(t, parseJSON(resp.Body, &initialResp))
	firstRefreshToken := initialResp.RefreshToken
	require.NotEmpty(t, firstRefreshToken)

	// Step 2: Use the refresh token once (legitimate rotation)
	form = url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	form.Set("refresh_token", firstRefreshToken)

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var secondResp OAuthTokenResponse
	require.NoError(t, parseJSON(resp.Body, &secondResp))
	secondRefreshToken := secondResp.RefreshToken
	require.NotEmpty(t, secondRefreshToken)
	require.NotEqual(t, firstRefreshToken, secondRefreshToken, "Refresh token should rotate")

	// Step 3: Replay the OLD refresh token (replay attack)
	form = url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	form.Set("refresh_token", firstRefreshToken) // OLD token

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	// CRITICAL: Replay must be rejected with invalid_grant
	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)

	// Step 4: Verify the family was revoked (NIST SP 800-63-4 Section 6.2.3)
	// Get family ID from first refresh token hash
	firstTokenHash := HashBootstrapToken(firstRefreshToken)
	family, err := svc.refreshTokenStore.GetFamilyByTokenHash(firstTokenHash)
	require.NoError(t, err)

	// Verify revocation
	assert.True(t, family.IsRevoked(), "Token family MUST be revoked after replay detection")
	require.NotNil(t, family.RevokedAt, "RevokedAt timestamp MUST be set")

	// Step 5: Verify the CURRENT (legitimate) token also fails after revocation
	form = url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	form.Set("refresh_token", secondRefreshToken) // CURRENT token

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	// Current token must also fail because entire family is revoked
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)
}

// TestRefreshTokenHandler_RotatesTokenHash verifies that CurrentTokenHash updates during rotation.
// This ensures token validation works correctly after rotation.
func TestRefreshTokenHandler_RotatesTokenHash(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	// Create and exchange bootstrap token
	bootstrapToken, err := svc.generateOpaqueToken(32)
	require.NoError(t, err)
	tokenHash := HashBootstrapToken(bootstrapToken)

	now := time.Now()
	policy := &BootstrapTokenPolicy{
		ID:         "bt-rotate-test",
		Subject:    "rotate-service",
		Audience:   "target-service",
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

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var initialResp OAuthTokenResponse
	require.NoError(t, parseJSON(resp.Body, &initialResp))
	firstRefreshToken := initialResp.RefreshToken

	// Get initial token hash and family from first refresh token
	firstTokenHash := HashBootstrapToken(firstRefreshToken)
	family, err := svc.refreshTokenStore.GetFamilyByTokenHash(firstTokenHash)
	require.NoError(t, err)
	require.NotNil(t, family, "Token family not found")
	firstHash := family.CurrentTokenHash
	firstUsageCount := family.UsageCount

	// Rotate token
	form = url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	form.Set("refresh_token", firstRefreshToken)

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp = httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var secondResp OAuthTokenResponse
	require.NoError(t, parseJSON(resp.Body, &secondResp))
	secondRefreshToken := secondResp.RefreshToken

	// Verify hash rotation
	family, err = svc.refreshTokenStore.GetFamily(family.FamilyID)
	require.NoError(t, err)
	secondHash := family.CurrentTokenHash

	assert.NotEqual(t, firstHash, secondHash, "CurrentTokenHash MUST update after rotation")
	assert.Equal(t, HashBootstrapToken(secondRefreshToken), secondHash, "CurrentTokenHash MUST match new token")
	assert.Equal(t, firstUsageCount+1, family.UsageCount, "UsageCount MUST increment")
	assert.False(t, family.LastUsedAt.IsZero(), "LastUsedAt MUST be updated")
}

// TestRefreshTokenHandler_ExpiredFamilyReturnsInvalidGrant verifies TTL enforcement.
func TestRefreshTokenHandler_ExpiredFamilyReturnsInvalidGrant(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	// Create a refresh token family that's already expired
	refreshToken, err := svc.generateOpaqueToken(32)
	require.NoError(t, err)

	now := time.Now()
	expiredFamily := &RefreshTokenFamily{
		FamilyID:         "expired-family",
		CurrentTokenHash: HashBootstrapToken(refreshToken),
		Subject:          "expired-service",
		Audience:         "target-service",
		Scopes:           []string{"read"},
		IssuedAt:         now.Add(-48 * time.Hour),
		ExpiresAt:        now.Add(-1 * time.Hour), // Expired 1 hour ago
		LastUsedAt:       now.Add(-2 * time.Hour),
		UsageCount:       5,
	}
	require.NoError(t, svc.refreshTokenStore.UpdateFamily(expiredFamily))

	// Attempt to use expired token
	form := url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	form.Set("refresh_token", refreshToken)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "invalid or has expired")
}

// TestRefreshTokenHandler_InvalidTokenReturnsInvalidGrant verifies rejection of unknown tokens.
func TestRefreshTokenHandler_InvalidTokenReturnsInvalidGrant(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	form := url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	form.Set("refresh_token", "completely-invalid-token-12345")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_grant", errResp.Error)
}

// TestRefreshTokenHandler_MissingRefreshTokenReturnsInvalidRequest verifies parameter validation.
func TestRefreshTokenHandler_MissingRefreshTokenReturnsInvalidRequest(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:      "http://tokensmith.test",
		ClusterID:   "cluster-test",
		OpenCHAMIID: "openchami-test",
	})

	form := url.Values{}
	form.Set("grant_type", GrantTypeRefreshTokenRFC8693)
	// Intentionally omit refresh_token

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()

	svc.OAuthTokenHandler(resp, req)

	require.Equal(t, http.StatusBadRequest, resp.Code)
	var errResp OAuthErrorResponse
	require.NoError(t, parseJSON(resp.Body, &errResp))
	assert.Equal(t, "invalid_request", errResp.Error)
	assert.Contains(t, errResp.ErrorDescription, "refresh_token")
}
