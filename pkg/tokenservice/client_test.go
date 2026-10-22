package tokenservice

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientInitialize_DoesNotRetryAfterResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "service-jwt-after-retry", TokenType: "Bearer", ExpiresIn: 1800, RefreshToken: "refresh-jwt-after-retry", RefreshExpiresIn: 86400, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("smd"), WithBootstrapMaxAttempts(5), WithBootstrapInitialBackoff(10*time.Millisecond), WithBootstrapMaxBackoff(20*time.Millisecond))
	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}

func TestServiceClientInitialize_DoesNotEnterBackoffAfterResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("smd"), WithBootstrapMaxAttempts(5), WithBootstrapInitialBackoff(100*time.Millisecond), WithBootstrapMaxBackoff(100*time.Millisecond))
	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "status=503")
}

func TestServiceClientRefreshTokenIfNeeded_RefreshTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "service-jwt", TokenType: "Bearer", ExpiresIn: 1, RefreshToken: "refresh-jwt", RefreshExpiresIn: 1, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("smd"), WithRefreshBefore(200*time.Millisecond))
	require.NoError(t, client.Initialize(context.Background()))
	time.Sleep(1200 * time.Millisecond)
	err := client.RefreshTokenIfNeeded(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRefreshTokenExpired))
	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshFailures, uint64(1))
	assert.Contains(t, stats.LastError, "refresh token expired")
}

func TestServiceClientStartAutoRefreshStopsOnRefreshTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "service-jwt", TokenType: "Bearer", ExpiresIn: 600, RefreshToken: "refresh-jwt", RefreshExpiresIn: 1, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "boot-service", "boot-service-id", "instance-1", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("hsm"), WithRefreshBefore(200*time.Millisecond), WithAutoRefreshInterval(20*time.Millisecond))
	require.NoError(t, client.Initialize(context.Background()))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); client.StartAutoRefresh(ctx) }()
	select {
	case <-done:
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("StartAutoRefresh did not exit after refresh token expiry")
	}
}
