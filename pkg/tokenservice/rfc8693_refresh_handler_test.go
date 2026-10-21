// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestOAuthTokenHandler_refresh_replay_revokes_family_and_survives_reopen(t *testing.T) {
	// Given
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(io.Discard))
	bootstrapResponse := httptest.NewRecorder()
	router.ServeHTTP(bootstrapResponse, bootstrapExchangeRequest(bootstrapToken))
	require.Equal(t, http.StatusOK, bootstrapResponse.Code)
	var bootstrapTokens OAuthTokenResponse
	require.NoError(t, json.NewDecoder(bootstrapResponse.Body).Decode(&bootstrapTokens))
	rotation := httptest.NewRecorder()
	router.ServeHTTP(rotation, refreshRequest(bootstrapTokens.RefreshToken))
	require.Equal(t, http.StatusOK, rotation.Code)
	var rotated OAuthTokenResponse
	require.NoError(t, json.NewDecoder(rotation.Body).Decode(&rotated))

	// When
	replay := httptest.NewRecorder()
	router.ServeHTTP(replay, refreshRequest(bootstrapTokens.RefreshToken))
	require.Equal(t, http.StatusBadRequest, replay.Code)
	reopened := newTestTokenService(t, svc.Config)
	newest := httptest.NewRecorder()
	reopened.newRouter(zerolog.New(io.Discard)).ServeHTTP(newest, refreshRequest(rotated.RefreshToken))

	// Then
	require.Equal(t, http.StatusBadRequest, newest.Code)
	var response OAuthErrorResponse
	require.NoError(t, json.NewDecoder(newest.Body).Decode(&response))
	require.Equal(t, "invalid_grant", response.Error)
}

func TestOAuthTokenHandler_refresh_replay_audits_revoked_family_without_credentials(t *testing.T) {
	// Given
	logs := useSynchronizedTestLogger(t)
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(logs))
	bootstrapResponse := httptest.NewRecorder()
	router.ServeHTTP(bootstrapResponse, bootstrapExchangeRequest(bootstrapToken))
	require.Equal(t, http.StatusOK, bootstrapResponse.Code)
	var bootstrapTokens OAuthTokenResponse
	require.NoError(t, json.NewDecoder(bootstrapResponse.Body).Decode(&bootstrapTokens))
	rotation := httptest.NewRecorder()
	router.ServeHTTP(rotation, refreshRequest(bootstrapTokens.RefreshToken))
	require.Equal(t, http.StatusOK, rotation.Code)
	var rotated OAuthTokenResponse
	require.NoError(t, json.NewDecoder(rotation.Body).Decode(&rotated))
	family, err := svc.refreshTokenStore.GetFamilyByTokenHash(HashBootstrapToken(bootstrapTokens.RefreshToken))
	require.NoError(t, err)
	logs.Reset()

	// When
	replay := httptest.NewRecorder()
	router.ServeHTTP(replay, refreshRequest(bootstrapTokens.RefreshToken))
	current := httptest.NewRecorder()
	router.ServeHTTP(current, refreshRequest(rotated.RefreshToken))

	// Then
	require.Equal(t, http.StatusBadRequest, replay.Code)
	require.Equal(t, http.StatusBadRequest, current.Code)
	require.Contains(t, logs.String(), string(AuditRefreshTokenReplayDetected))
	require.Contains(t, logs.String(), string(AuditRefreshTokenFamilyRevoked))
	require.Contains(t, logs.String(), family.Subject)
	require.Contains(t, logs.String(), family.Audience)
	require.Contains(t, logs.String(), family.FamilyID)
	require.Contains(t, logs.String(), "last_used_at")
	require.Contains(t, logs.String(), "\"usage_count\":1")
	require.NotContains(t, logs.String(), bootstrapToken)
	require.NotContains(t, logs.String(), bootstrapTokens.RefreshToken)
	require.NotContains(t, logs.String(), rotated.RefreshToken)
	require.NotContains(t, logs.String(), rotated.AccessToken)
}

func TestOAuthTokenHandler_refresh_mint_failure_does_not_rotate_family(t *testing.T) {
	// Given
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(io.Discard))
	bootstrapResponse := httptest.NewRecorder()
	router.ServeHTTP(bootstrapResponse, bootstrapExchangeRequest(bootstrapToken))
	require.Equal(t, http.StatusOK, bootstrapResponse.Code)
	var bootstrapTokens OAuthTokenResponse
	require.NoError(t, json.NewDecoder(bootstrapResponse.Body).Decode(&bootstrapTokens))
	originalMinter := generateServiceTokenForOAuth
	generateServiceTokenForOAuth = func(_ *TokenService, _ string, _ string, _ []string, _ time.Duration) (mintedAccessToken, error) {
		return mintedAccessToken{}, errors.New("injected signing failure")
	}

	// When
	failed := httptest.NewRecorder()
	router.ServeHTTP(failed, refreshRequest(bootstrapTokens.RefreshToken))
	generateServiceTokenForOAuth = originalMinter
	t.Cleanup(func() { generateServiceTokenForOAuth = originalMinter })
	original := httptest.NewRecorder()
	router.ServeHTTP(original, refreshRequest(bootstrapTokens.RefreshToken))

	// Then
	require.Equal(t, http.StatusInternalServerError, failed.Code)
	require.Equal(t, http.StatusOK, original.Code)
}

func TestOAuthTokenHandler_concurrent_refresh_reuse_revokes_family(t *testing.T) {
	// Given
	logs := useSynchronizedTestLogger(t)
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(logs))
	bootstrapResponse := httptest.NewRecorder()
	router.ServeHTTP(bootstrapResponse, bootstrapExchangeRequest(bootstrapToken))
	require.Equal(t, http.StatusOK, bootstrapResponse.Code)
	var bootstrapTokens OAuthTokenResponse
	require.NoError(t, json.NewDecoder(bootstrapResponse.Body).Decode(&bootstrapTokens))
	start := make(chan struct{})
	statuses := make(chan int, 20)
	var workers sync.WaitGroup

	// When
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			response := httptest.NewRecorder()
			router.ServeHTTP(response, refreshRequest(bootstrapTokens.RefreshToken))
			statuses <- response.Code
		}()
	}
	close(start)
	workers.Wait()
	close(statuses)

	// Then
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
			continue
		}
		require.Equal(t, http.StatusBadRequest, status)
	}
	require.Equal(t, 1, successes)
	require.Contains(t, logs.String(), string(AuditRefreshTokenReplayDetected))
	require.Contains(t, logs.String(), string(AuditRefreshTokenFamilyRevoked))
	family, err := svc.refreshTokenStore.GetFamilyByTokenHash(HashBootstrapToken(bootstrapTokens.RefreshToken))
	require.NoError(t, err)
	require.NotNil(t, family.RevokedAt)
}

func refreshRequest(refreshToken string) *http.Request {
	form := url.Values{
		"grant_type":    {GrantTypeRefreshTokenRFC8693},
		"refresh_token": {refreshToken},
	}
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}
