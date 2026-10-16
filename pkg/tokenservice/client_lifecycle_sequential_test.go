// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func TestServiceClientGetToken_ReacquiresMTLSSessionAfterRefreshFamilyExpiry(t *testing.T) {
	// Given: an expired refresh family and configured service identity material.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	var serviceIdentityCalls atomic.Int32
	var bootstrapCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			assert.NotEmpty(t, r.TLS.PeerCertificates)
			assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
		case "/oauth/token":
			bootstrapCalls.Add(1)
			http.Error(w, "bootstrap must not be replayed", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))

	// When: the expired access token needs renewal.
	err := client.GetToken(context.Background())

	// Then: the client replaces the family through mTLS without replaying bootstrap credentials.
	require.NoError(t, err)
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, int32(0), bootstrapCalls.Load())
	assert.Equal(t, "reacquired-access", client.GetServiceToken().Token)
}

func TestServiceClientGetToken_ReturnsMTLSReacquisitionFailure(t *testing.T) {
	// Given: an expired refresh family whose mTLS session request fails.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	var serviceIdentityCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/service-identity/session", r.URL.Path)
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		serviceIdentityCalls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(server.Client()))

	// When: the access token needs renewal.
	err := client.GetToken(context.Background())

	// Then: the mTLS error is returned and the old family remains untouched.
	require.Error(t, err)
	assert.ErrorContains(t, err, "service identity reauthentication:")
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, "old-access", client.GetServiceToken().Token)
	client.mu.RLock()
	assert.Equal(t, "expired-refresh", client.refreshToken)
	client.mu.RUnlock()
}

func TestServiceClientGetToken_ReturnsTerminalExpiryWithoutServiceIdentity(t *testing.T) {
	// Given: an expired refresh family without configured service identity material.
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "bootstrap must not be replayed", http.StatusBadRequest)
	}))
	defer server.Close()

	client := newTerminallyExpiredServiceClient(t, server.URL, "", "")

	// When: the access token needs renewal.
	err := client.GetToken(context.Background())

	// Then: terminal expiry is returned exactly and no network request is made.
	require.ErrorIs(t, err, ErrRefreshTokenExpired)
	assert.Equal(t, ErrRefreshTokenExpired, err)
	assert.ErrorIs(t, err, ErrRefreshTokenExpired)
	assert.Equal(t, int32(0), requests.Load())
}

func TestServiceClientGetToken_UsesFreshAccessTokenAfterRefreshFamilyExpiry(t *testing.T) {
	// Given: a fresh access token backed by a terminally expired refresh family.
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "fresh access token must not trigger renewal", http.StatusBadRequest)
	}))
	defer server.Close()

	client := newTerminallyExpiredServiceClient(t, server.URL, "", "")
	client.mu.Lock()
	client.token.ExpiresAt = time.Now().Add(time.Hour)
	client.mu.Unlock()

	// When: the caller requests a service token.
	err := client.GetToken(context.Background())

	// Then: the valid access token is retained without any lifecycle request.
	require.NoError(t, err)
	assert.Equal(t, "old-access", client.GetServiceToken().Token)
	assert.Equal(t, int32(0), requests.Load())
}

func TestServiceClientGetToken_AlreadyCanceledWithFreeGateMakesNoRequest(t *testing.T) {
	// Given: an expired client whose lifecycle gate is free.
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "canceled caller must not request a token", http.StatusBadRequest)
	}))
	defer server.Close()

	client := newTerminallyExpiredServiceClient(t, server.URL, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// When: an already-canceled caller attempts token acquisition.
	err := client.GetToken(ctx)

	// Then: cancellation is returned before any request is selected.
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(0), requests.Load())
}

func TestServiceClientGetToken_DoesNotUseMTLSForTransientRefreshFailure(t *testing.T) {
	// Given: a non-expired refresh family whose refresh request fails transiently.
	_, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	var refreshCalls atomic.Int32
	var serviceIdentityCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshCalls.Add(1)
			http.Error(w, "temporary", http.StatusServiceUnavailable)
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			assert.NoError(t, writeLifecycleToken(w, "unexpected", "unexpected"))
		}
	}))
	defer server.Close()

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath)
	client.mu.Lock()
	client.refreshExpiresAt = time.Now().Add(time.Hour)
	client.mu.Unlock()

	// When: refresh renewal fails.
	err := client.GetToken(context.Background())

	// Then: the refresh failure is propagated without changing authentication modes.
	require.Error(t, err)
	assert.Equal(t, int32(1), refreshCalls.Load())
	assert.Equal(t, int32(0), serviceIdentityCalls.Load())
}

func TestServiceClientGetToken_RejectsPlaintextServiceIdentitySession(t *testing.T) {
	// Given: terminal expiry with configured mTLS material and a plaintext TokenSmith URL.
	_, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.NoError(t, writeLifecycleToken(w, "unexpected", "unexpected"))
	}))
	defer server.Close()

	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath)

	// When: terminal expiry attempts service identity reauthentication.
	err := client.GetToken(context.Background())

	// Then: plaintext service identity is rejected before a request is made.
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTLSClientMaterial))
	assert.Equal(t, int32(0), requests.Load())
}

func newTerminallyExpiredServiceClient(t *testing.T, serverURL, certPath, keyPath string, options ...ServiceClientOption) *ServiceClient {
	t.Helper()
	opts := []ServiceClientOption{
		WithBootstrapToken("consumed-bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(time.Minute),
	}
	if certPath != "" || keyPath != "" {
		opts = append(opts, WithServiceIdentityCertKey(certPath, keyPath))
	}
	opts = append(opts, options...)
	client := NewServiceClientWithOptions(serverURL, "metadata-service", "metadata-service-id", "instance-1", "cluster-1", opts...)
	client.mu.Lock()
	client.token = &ServiceToken{Token: "old-access", ExpiresAt: time.Now().Add(-time.Minute)}
	client.refreshToken = "expired-refresh"
	client.refreshExpiresAt = time.Now().Add(-time.Minute)
	client.mu.Unlock()
	return client
}

func writeLifecycleToken(w http.ResponseWriter, accessToken, refreshToken string) error {
	return json.NewEncoder(w).Encode(OAuthTokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: 3600,
		IssuedTokenType:  AccessTokenTypeRFC8693,
	})
}

func newServiceIdentityTLSServer(t *testing.T, caPEM []byte, handler http.Handler) *httptest.Server {
	t.Helper()
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}
