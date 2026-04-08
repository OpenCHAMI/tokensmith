// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientInitializeWithOptions(t *testing.T) {
	var receivedGrantType, receivedSubjectToken, receivedSubjectTokenType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		receivedGrantType = r.FormValue("grant_type")
		receivedSubjectToken = r.FormValue("subject_token")
		receivedSubjectTokenType = r.FormValue("subject_token_type")
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt-1",
			TokenType:        "Bearer",
			ExpiresIn:        1800,
			RefreshToken:     "refresh-jwt-1",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"boot-service",
		"boot-service-id",
		"instance-1",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("hsm"),
		WithScopes([]string{"hsm:read", " hsm:write "}),
	)

	err := client.Initialize(context.Background())
	require.NoError(t, err)

	token := client.GetServiceToken()
	require.NotNil(t, token)
	assert.Equal(t, "service-jwt-1", token.Token)
	assert.Equal(t, GrantTypeTokenExchange, receivedGrantType)
	assert.Equal(t, "bootstrap-token", receivedSubjectToken)
	assert.Equal(t, BootstrapTokenTypeRFC8693, receivedSubjectTokenType)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.RefreshSuccesses)
	assert.Equal(t, uint64(0), stats.RefreshFailures)
	assert.Equal(t, "", stats.LastError)
	assert.True(t, stats.HasToken)
	assert.True(t, stats.HasRefreshToken)
	assert.False(t, stats.LastSuccess.IsZero())
}

func TestServiceClientInitializeMissingBootstrapToken(t *testing.T) {
	client := NewServiceClientWithOptions(
		"http://tokensmith.local",
		"boot-service",
		"boot-service-id",
		"instance-1",
		"cluster-1",
		WithTargetService("hsm"),
	)

	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingBootstrapToken))
}

func TestServiceClientRefreshTokenIfNeededBoundary(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        600,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(3*time.Minute),
	)

	require.NoError(t, client.GetToken(context.Background()))
	assert.Equal(t, int32(1), calls.Load())

	// Existing token remains valid beyond refresh threshold; no additional exchange.
	require.NoError(t, client.RefreshTokenIfNeeded(context.Background()))
	assert.Equal(t, int32(1), calls.Load())
}

func TestServiceClientRefreshTokenIfNeeded_UsesRefreshGrant(t *testing.T) {
	var calls atomic.Int32
	var grantTypes [2]string
	var tokenValues [2]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		i := int(calls.Add(1)) - 1
		if i < 2 {
			grantTypes[i] = r.FormValue("grant_type")
			if r.FormValue("subject_token") != "" {
				tokenValues[i] = r.FormValue("subject_token")
			} else {
				tokenValues[i] = r.FormValue("refresh_token")
			}
		}

		if calls.Load() == 1 {
			_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
				AccessToken:      "access-1",
				TokenType:        "Bearer",
				ExpiresIn:        1,
				RefreshToken:     "refresh-1",
				RefreshExpiresIn: 3600,
				IssuedTokenType:  AccessTokenTypeRFC8693,
			})
			return
		}

		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "access-2",
			TokenType:        "Bearer",
			ExpiresIn:        600,
			RefreshToken:     "refresh-2",
			RefreshExpiresIn: 3600,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(2*time.Second),
	)

	require.NoError(t, client.Initialize(context.Background()))
	time.Sleep(60 * time.Millisecond)
	require.NoError(t, client.RefreshTokenIfNeeded(context.Background()))

	assert.Equal(t, int32(2), calls.Load())
	assert.Equal(t, GrantTypeTokenExchange, grantTypes[0])
	assert.Equal(t, "bootstrap-token", tokenValues[0])
	assert.Equal(t, GrantTypeRefreshTokenRFC8693, grantTypes[1])
	assert.Equal(t, "refresh-1", tokenValues[1])
}

func TestServiceClientConcurrentRefreshRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        1,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(2*time.Second),
	)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = client.RefreshTokenIfNeeded(context.Background())
		}()
	}
	wg.Wait()

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshSuccesses, uint64(1))
	assert.GreaterOrEqual(t, calls.Load(), int32(1))
}

func TestServiceClientInitializeRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := calls.Add(1)
		if count < 3 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}

		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt-after-retry",
			TokenType:        "Bearer",
			ExpiresIn:        1800,
			RefreshToken:     "refresh-jwt-after-retry",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithBootstrapMaxAttempts(5),
		WithBootstrapInitialBackoff(10*time.Millisecond),
		WithBootstrapMaxBackoff(20*time.Millisecond),
	)

	err := client.Initialize(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(3), calls.Load())

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshFailures, uint64(2))
	assert.GreaterOrEqual(t, stats.RefreshSuccesses, uint64(1))
	assert.True(t, stats.HasToken)
}

func TestServiceClientInitializeCanceledDuringBackoff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithBootstrapMaxAttempts(5),
		WithBootstrapInitialBackoff(100*time.Millisecond),
		WithBootstrapMaxBackoff(100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := client.Initialize(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap token exchange canceled")
}

func TestServiceClientRefreshTokenIfNeeded_RefreshTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        1,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 1,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(200*time.Millisecond),
	)

	require.NoError(t, client.Initialize(context.Background()))
	time.Sleep(1200 * time.Millisecond) // wait for both access and refresh tokens to expire (ExpiresIn: 1s)

	err := client.RefreshTokenIfNeeded(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRefreshTokenExpired))

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshFailures, uint64(1))
	assert.Contains(t, stats.LastError, "refresh token expired")
}

func TestServiceClientStartAutoRefreshStopsOnRefreshTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        600,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 1,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"boot-service",
		"boot-service-id",
		"instance-1",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("hsm"),
		WithRefreshBefore(200*time.Millisecond),
		WithAutoRefreshInterval(20*time.Millisecond),
	)

	require.NoError(t, client.Initialize(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})

	go func() {
		defer close(done)
		client.StartAutoRefresh(ctx)
	}()

	select {
	case <-done:
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("StartAutoRefresh did not exit after refresh token expiry")
	}
}
