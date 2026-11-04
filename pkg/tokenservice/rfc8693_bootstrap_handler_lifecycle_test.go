// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestOAuthTokenHandler_bootstrap_replay_remains_consumed_after_reopen(t *testing.T) {
	// Given
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.Nop())
	first := httptest.NewRecorder()
	router.ServeHTTP(first, bootstrapExchangeRequest(bootstrapToken))
	require.Equal(t, http.StatusOK, first.Code)
	config := svc.Config
	reopened := newTestTokenService(t, config)

	// When
	replay := httptest.NewRecorder()
	reopened.newRouter(zerolog.New(io.Discard)).ServeHTTP(replay, bootstrapExchangeRequest(bootstrapToken))

	// Then
	require.Equal(t, http.StatusBadRequest, replay.Code)
	var response OAuthErrorResponse
	require.NoError(t, json.NewDecoder(replay.Body).Decode(&response))
	require.Equal(t, "invalid_grant", response.Error)
}

func TestOAuthTokenHandler_bootstrap_audit_and_policy_use_JTI_not_access_JWT(t *testing.T) {
	// Given
	logs := useSynchronizedTestLogger(t)
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	response := httptest.NewRecorder()

	// When
	svc.newRouter(zerolog.New(logs)).ServeHTTP(response, bootstrapExchangeRequest(bootstrapToken))

	// Then
	require.Equal(t, http.StatusOK, response.Code)
	var tokenResponse OAuthTokenResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&tokenResponse))
	claims, _, err := svc.TokenManager.ParseToken(tokenResponse.AccessToken)
	require.NoError(t, err)
	require.NotEmpty(t, claims.ID)
	require.Contains(t, logs.String(), claims.ID)
	require.NotContains(t, logs.String(), tokenResponse.AccessToken)
	require.NotContains(t, logs.String(), bootstrapToken)
	require.NotContains(t, logs.String(), tokenResponse.RefreshToken)
	policy, err := svc.bootstrapTokenStore.GetPolicy(HashBootstrapToken(bootstrapToken))
	require.NoError(t, err)
	require.Equal(t, claims.ID, policy.IssuedAccessTokenID)
	require.NotEqual(t, tokenResponse.AccessToken, policy.IssuedAccessTokenID)
}

func TestOAuthTokenHandler_bootstrap_mint_failure_leaves_policy_consumed(t *testing.T) {
	// Given
	svc := newTestTokenService(t, Config{
		Issuer:                         "http://tokensmith.test",
		ClusterID:                      "cluster-test",
		OpenCHAMIID:                    "openchami-test",
		RFC8693BootstrapStorePath:      filepath.Join(t.TempDir(), "bootstrap"),
		RFC8693RefreshStorePath:        filepath.Join(t.TempDir(), "refresh"),
		ServiceIdentityPolicyStorePath: filepath.Join(t.TempDir(), "identities"),
	})
	bootstrapToken := "bootstrap-token-with-invalid-policy"
	now := time.Now().UTC()
	require.NoError(t, svc.bootstrapTokenStore.SavePolicy(&BootstrapTokenPolicy{
		ID: "invalid-policy", Audience: "metadata-service", TokenHash: HashBootstrapToken(bootstrapToken), ExpiresAt: now.Add(time.Minute), RefreshTTL: time.Hour,
	}))

	// When
	response := httptest.NewRecorder()
	svc.newRouter(zerolog.New(io.Discard)).ServeHTTP(response, bootstrapExchangeRequest(bootstrapToken))

	// Then
	require.Equal(t, http.StatusInternalServerError, response.Code)
	policy, err := svc.bootstrapTokenStore.GetPolicy(HashBootstrapToken(bootstrapToken))
	require.NoError(t, err)
	require.NotNil(t, policy.ConsumedAt)
}
