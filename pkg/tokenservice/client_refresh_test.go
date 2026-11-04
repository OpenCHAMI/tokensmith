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
	var grantType, subjectToken, subjectTokenType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		grantType, subjectToken, subjectTokenType = r.FormValue("grant_type"), r.FormValue("subject_token"), r.FormValue("subject_token_type")
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "service-jwt-1", TokenType: "Bearer", ExpiresIn: 1800, RefreshToken: "refresh-jwt-1", RefreshExpiresIn: 86400, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "boot-service", "boot-service-id", "instance-1", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("hsm"))
	require.NoError(t, client.Initialize(context.Background()))
	token := client.GetServiceToken()
	require.NotNil(t, token)
	assert.Equal(t, "service-jwt-1", token.Token)
	assert.Equal(t, GrantTypeTokenExchange, grantType)
	assert.Equal(t, "bootstrap-token", subjectToken)
	assert.Equal(t, BootstrapTokenTypeRFC8693, subjectTokenType)
	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.RefreshSuccesses)
	assert.Equal(t, uint64(0), stats.RefreshFailures)
	assert.Equal(t, "", stats.LastError)
	assert.True(t, stats.HasToken)
	assert.True(t, stats.HasRefreshToken)
	assert.False(t, stats.LastSuccess.IsZero())
}

func TestServiceClientInitializeMissingBootstrapToken(t *testing.T) {
	client := NewServiceClientWithOptions("http://tokensmith.local", "boot-service", "boot-service-id", "instance-1", "cluster-1", WithTargetService("hsm"))
	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingBootstrapToken))
}

func TestServiceClientRefreshTokenIfNeededBoundary(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "service-jwt", TokenType: "Bearer", ExpiresIn: 600, RefreshToken: "refresh-jwt", RefreshExpiresIn: 86400, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("smd"), WithRefreshBefore(3*time.Minute))
	require.NoError(t, client.GetToken(context.Background()))
	assert.Equal(t, int32(1), calls.Load())
	require.NoError(t, client.RefreshTokenIfNeeded(context.Background()))
	assert.Equal(t, int32(1), calls.Load())
}

func TestServiceClientRefreshTokenIfNeeded_UsesRefreshGrant(t *testing.T) {
	var calls atomic.Int32
	var grantTypes, tokenValues [2]string
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
			_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "access-1", TokenType: "Bearer", ExpiresIn: 1, RefreshToken: "refresh-1", RefreshExpiresIn: 3600, IssuedTokenType: AccessTokenTypeRFC8693})
			return
		}
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "access-2", TokenType: "Bearer", ExpiresIn: 600, RefreshToken: "refresh-2", RefreshExpiresIn: 3600, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("smd"), WithRefreshBefore(2*time.Second))
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
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "service-jwt", TokenType: "Bearer", ExpiresIn: 1, RefreshToken: "refresh-jwt", RefreshExpiresIn: 86400, IssuedTokenType: AccessTokenTypeRFC8693})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "metadata-service", "metadata-service-id", "instance-2", "cluster-1", WithBootstrapToken("bootstrap-token"), WithTargetService("smd"), WithRefreshBefore(2*time.Second))
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() { defer group.Done(); _ = client.RefreshTokenIfNeeded(context.Background()) }()
	}
	group.Wait()
	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshSuccesses, uint64(1))
	assert.GreaterOrEqual(t, calls.Load(), int32(1))
}
