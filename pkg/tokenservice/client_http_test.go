// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type clientRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip clientRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestServiceClientInitialize_RetriesOnlyPreSendFailure(t *testing.T) {
	// Given: the first bootstrap attempt fails before any request is sent.
	var attempts atomic.Int32
	transport := clientRoundTripper(func(request *http.Request) (*http.Response, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("dial failed")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"access","expires_in":60,"refresh_token":"refresh","refresh_expires_in":60}`)),
			Header:     make(http.Header),
		}, nil
	})
	client := NewServiceClientWithOptions("https://tokensmith.test", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"), WithHTTPClient(&http.Client{Transport: transport}), WithBootstrapMaxAttempts(2))

	// When: initialization runs.
	err := client.Initialize(context.Background())

	// Then: the pre-send error is retried exactly once.
	require.NoError(t, err)
	assert.Equal(t, int32(2), attempts.Load())
}

func TestServiceClientGetToken_RedactsAndBoundsOAuthError(t *testing.T) {
	// Given: an OAuth endpoint returns a hostile secret-bearing body.
	secret := "bootstrap-secret-and-jwt"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"invalid_grant","error_description":"` + secret + `"}` + strings.Repeat("x", maximumErrorBodyBytes)))
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "service", "id", "instance", "cluster", WithBootstrapToken(secret), WithTargetService("target"))

	// When: token acquisition receives the hostile response.
	err := client.GetToken(context.Background())

	// Then: the externally visible failure contains only bounded safe metadata.
	require.Error(t, err)
	assert.ErrorContains(t, err, "status=400")
	assert.ErrorContains(t, err, "oauth_error=invalid_grant")
	assert.NotContains(t, err.Error(), secret)
	assert.NotContains(t, client.Stats().LastError, secret)
	assert.Less(t, len(err.Error()), 256)
	assert.Equal(t, uint64(1), client.Stats().RefreshFailures)
}

func TestServiceClientGetToken_ForcesRotationWhenTokenIsFresh(t *testing.T) {
	// Given: a client with a fresh access and refresh token family.
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		_, _ = writer.Write([]byte(`{"access_token":"access","expires_in":3600,"refresh_token":"refresh","refresh_expires_in":3600}`))
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"))
	require.NoError(t, client.Initialize(context.Background()))

	// When: the public GetToken API is invoked.
	require.NoError(t, client.ForceRefresh(context.Background()))

	// Then: it performs one explicit rotation rather than returning the cached token.
	assert.Equal(t, int32(2), calls.Load())
	assert.Equal(t, uint64(2), client.Stats().RefreshSuccesses)
}

func TestServiceClientGetToken_RecordsPreflightFailureOnce(t *testing.T) {
	// Given: a client with an invalid endpoint that fails while constructing its request.
	client := NewServiceClientWithOptions("://invalid", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"))

	// When: it attempts acquisition.
	err := client.GetToken(context.Background())

	// Then: the top-level operation records one sanitized failure.
	require.Error(t, err)
	assert.Equal(t, uint64(1), client.Stats().RefreshFailures)
	assert.NotContains(t, client.Stats().LastError, "bootstrap")
}

func TestServiceClientCallTargetService_DoesNotFollowRedirectWithAuthorization(t *testing.T) {
	// Given: a target that redirects to an independently observed destination.
	var destinationCalls atomic.Int32
	var destinationAuthorization atomic.Value
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		destinationCalls.Add(1)
		destinationAuthorization.Store(request.Header.Get("Authorization"))
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(destination.Close)
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusFound)
	}))
	t.Cleanup(target.Close)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(`{"access_token":"access","expires_in":3600,"refresh_token":"refresh","refresh_expires_in":3600}`))
	}))
	t.Cleanup(tokenServer.Close)
	client := NewServiceClientWithOptions(tokenServer.URL, "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"))
	require.NoError(t, client.Initialize(context.Background()))

	// When: the authorized target request receives a redirect.
	err := client.CallTargetService(context.Background(), target.URL)

	// Then: no destination request is made and the caller receives a safe redirect error.
	require.Error(t, err)
	assert.ErrorContains(t, err, "status=302")
	assert.Equal(t, int32(0), destinationCalls.Load())
	assert.Empty(t, destinationAuthorization.Load())
}

func TestServiceClientGetToken_RecordsEveryPreflightFailureOnce(t *testing.T) {
	tests := []struct {
		name   string
		client *ServiceClient
		ctx    context.Context
	}{
		{
			name:   "empty URL",
			client: NewServiceClientWithOptions("", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target")),
			ctx:    context.Background(),
		},
		{
			name:   "empty target",
			client: NewServiceClientWithOptions("https://tokensmith.test", "", "id", "instance", "cluster", WithBootstrapToken("bootstrap")),
			ctx:    context.Background(),
		},
		{
			name:   "partial service identity",
			client: NewServiceClientWithOptions("https://tokensmith.test", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"), WithServiceIdentityCertKey("cert", "")),
			ctx:    context.Background(),
		},
		{
			name:   "already canceled context",
			client: NewServiceClientWithOptions("https://tokensmith.test", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target")),
			ctx:    canceledContext(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: a client that cannot begin acquisition.
			// When: the public GetToken entrypoint is invoked.
			err := test.client.GetToken(test.ctx)
			// Then: it records exactly one observable failed lifecycle outcome.
			require.Error(t, err)
			stats := test.client.Stats()
			assert.Equal(t, uint64(1), stats.RefreshFailures)
			assert.False(t, stats.LastRefresh.IsZero())
			assert.NotEmpty(t, stats.LastError)
		})
	}
}

func TestServiceClientInitialize_CanceledContextRecordsOneFailureWithoutRequest(t *testing.T) {
	// Given: an already-canceled initialization context and a client with a counting transport.
	var requests atomic.Int32
	client := NewServiceClientWithOptions("https://tokensmith.test", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"), WithHTTPClient(&http.Client{Transport: clientRoundTripper(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	})}))

	// When: Initialize is called.
	err := client.Initialize(canceledContext())

	// Then: it publishes one top-level failure without reaching the network.
	require.ErrorIs(t, err, context.Canceled)
	stats := client.Stats()
	assert.Equal(t, int32(0), requests.Load())
	assert.Equal(t, uint64(1), stats.RefreshFailures)
	assert.False(t, stats.LastRefresh.IsZero())
	assert.NotEmpty(t, stats.LastError)
}

func TestServiceClientInitialize_DoesNotRetryRefreshLifecycle(t *testing.T) {
	// Given: a client whose first initialization produced a refresh token.
	var requests atomic.Int32
	transport := clientRoundTripper(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"access_token":"access","expires_in":60,"refresh_token":"refresh","refresh_expires_in":60}`)), Header: make(http.Header)}, nil
		}
		return nil, errors.New("pre-send refresh failure")
	})
	client := NewServiceClientWithOptions("https://tokensmith.test", "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"), WithHTTPClient(&http.Client{Transport: transport}), WithBootstrapMaxAttempts(5))
	require.NoError(t, client.Initialize(context.Background()))

	// When: Initialize is called again with the refresh family present.
	err := client.Initialize(context.Background())

	// Then: refresh runs exactly once even when its transport failure is pre-send.
	require.Error(t, err)
	assert.Equal(t, int32(2), requests.Load())
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
