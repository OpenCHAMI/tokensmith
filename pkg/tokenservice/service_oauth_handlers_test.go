// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
