// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientGetToken_DoesNotUseMTLSForTransientRefreshFailure(t *testing.T) {
	// Given: valid mTLS material and refresh failures that are not terminal OAuth invalid_grant.
	for _, test := range []struct {
		name          string
		newClient     func(t *testing.T, certPath, keyPath string) (*ServiceClient, *atomic.Int32)
		wantStatus    int
		wantOAuthCode string
	}{
		{
			name: "server error",
			newClient: func(t *testing.T, certPath, keyPath string) (*ServiceClient, *atomic.Int32) {
				t.Helper()
				var refreshCalls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, "/oauth/token", r.URL.Path)
					refreshCalls.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
					assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "server_error"}))
				}))
				t.Cleanup(server.Close)
				client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath)
				return client, &refreshCalls
			},
			wantStatus:    http.StatusServiceUnavailable,
			wantOAuthCode: "server_error",
		},
		{
			name: "transport error",
			newClient: func(t *testing.T, certPath, keyPath string) (*ServiceClient, *atomic.Int32) {
				t.Helper()
				var attempts atomic.Int32
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
					attempts.Add(1)
					return nil, errors.New("dial refused")
				}
				client := newTerminallyExpiredServiceClient(t, "https://tokensmith.test", certPath, keyPath, WithHTTPClient(&http.Client{Transport: transport}))
				return client, &attempts
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
			client, attempts := test.newClient(t, certPath, keyPath)
			client.mu.Lock()
			client.refreshExpiresAt = time.Now().Add(time.Hour)
			client.mu.Unlock()

			// When: refresh renewal fails.
			err := client.ForceRefresh(context.Background())

			// Then: the typed transient error is returned without an mTLS replacement.
			require.Error(t, err)
			var requestErr *tokenRequestError
			require.ErrorAs(t, err, &requestErr)
			assert.Equal(t, test.wantStatus, requestErr.status)
			assert.Equal(t, test.wantOAuthCode, requestErr.oauthCode)
			assert.Equal(t, int32(1), attempts.Load())
		})
	}
}

func TestServiceClientForceRefresh_ReacquiresMTLSSessionAfterRefreshInvalidGrant(t *testing.T) {
	// Given: a refreshable family rejected with a terminal OAuth invalid_grant and valid mTLS material.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	var refreshCalls atomic.Int32
	var serviceIdentityCalls atomic.Int32
	var bootstrapCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshCalls.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"}))
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			assert.NotEmpty(t, r.TLS.PeerCertificates)
			assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
		default:
			bootstrapCalls.Add(1)
			http.Error(w, "bootstrap must not be replayed", http.StatusBadRequest)
		}
	}))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(&http.Client{Transport: transport}))
	client.mu.Lock()
	client.refreshExpiresAt = time.Now().Add(time.Hour)
	client.mu.Unlock()

	// When: refresh receives the terminal OAuth error.
	err = client.ForceRefresh(context.Background())

	// Then: exactly one mTLS replacement succeeds and bootstrap is never replayed.
	require.NoError(t, err)
	assert.Equal(t, int32(1), refreshCalls.Load())
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, int32(0), bootstrapCalls.Load())
	assert.Equal(t, "reacquired-access", client.GetServiceToken().Token)
}

func TestServiceClientForceRefresh_DoesNotReacquireMTLSAfterServerErrorInvalidGrant(t *testing.T) {
	// Given: valid mTLS material and a non-standard 5xx response carrying invalid_grant.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	var refreshCalls atomic.Int32
	var serviceIdentityCalls atomic.Int32
	var bootstrapCalls atomic.Int32
	server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshCalls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"}))
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			assert.NoError(t, writeLifecycleToken(w, "unexpected", "unexpected"))
		default:
			bootstrapCalls.Add(1)
			http.Error(w, "bootstrap must not be replayed", http.StatusBadRequest)
		}
	}))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(&http.Client{Transport: transport}))
	client.mu.Lock()
	client.refreshExpiresAt = time.Now().Add(time.Hour)
	client.mu.Unlock()

	// When: refresh returns the malformed terminal-looking response.
	err = client.ForceRefresh(context.Background())

	// Then: the typed 5xx error is returned without mTLS recovery or bootstrap replay.
	require.Error(t, err)
	var requestErr *tokenRequestError
	require.ErrorAs(t, err, &requestErr)
	assert.Equal(t, http.StatusServiceUnavailable, requestErr.status)
	assert.Equal(t, "invalid_grant", requestErr.oauthCode)
	assert.Equal(t, int32(1), refreshCalls.Load())
	assert.Equal(t, int32(0), serviceIdentityCalls.Load())
	assert.Equal(t, int32(0), bootstrapCalls.Load())
}

func TestServiceClientForceRefresh_ReacquiresMTLSSessionOnlyForCompleteInvalidGrant(t *testing.T) {
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	tests := []struct {
		name          string
		status        int
		body          string
		wantRecovery  bool
		wantTruncated bool
		wantOAuthCode string
	}{
		{"canonical invalid_grant", http.StatusBadRequest, `{"error":"invalid_grant"}`, true, false, "invalid_grant"},
		{"trailing garbage", http.StatusBadRequest, `{"error":"invalid_grant"}garbage`, false, false, ""},
		{"trailing json document", http.StatusBadRequest, `{"error":"invalid_grant"}{"error":"invalid_grant"}`, false, false, ""},
		{"malformed json", http.StatusBadRequest, `{"error":"invalid_grant"`, false, false, ""},
		{"oversized truncated body", http.StatusBadRequest, `{"error":"invalid_grant"}` + strings.Repeat("x", maximumErrorBodyBytes), false, true, ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var refreshCalls atomic.Int32
			var serviceIdentityCalls atomic.Int32
			var bootstrapCalls atomic.Int32
			server := newServiceIdentityTLSServer(t, caPEM, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oauth/token":
					refreshCalls.Add(1)
					w.WriteHeader(test.status)
					_, _ = w.Write([]byte(test.body))
				case "/service-identity/session":
					serviceIdentityCalls.Add(1)
					assert.NotEmpty(t, r.TLS.PeerCertificates)
					assert.NoError(t, writeLifecycleToken(w, "reacquired-access", "reacquired-refresh"))
				default:
					bootstrapCalls.Add(1)
					http.Error(w, "bootstrap must not be replayed", http.StatusBadRequest)
				}
			}))
			certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
			require.NoError(t, err)
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
			client := newTerminallyExpiredServiceClient(t, server.URL, certPath, keyPath, WithHTTPClient(&http.Client{Transport: transport}))
			client.mu.Lock()
			client.refreshExpiresAt = time.Now().Add(time.Hour)
			client.mu.Unlock()

			// When: refresh receives the response body under test.
			err = client.ForceRefresh(context.Background())

			// Then: only a complete, non-truncated invalid_grant response triggers mTLS recovery.
			if test.wantRecovery {
				require.NoError(t, err)
				assert.Equal(t, int32(1), serviceIdentityCalls.Load())
				assert.Equal(t, "reacquired-access", client.GetServiceToken().Token)
			} else {
				require.Error(t, err)
				var requestErr *tokenRequestError
				require.ErrorAs(t, err, &requestErr)
				assert.Equal(t, test.status, requestErr.status)
				assert.Equal(t, test.wantOAuthCode, requestErr.oauthCode)
				assert.Equal(t, test.wantTruncated, requestErr.truncated)
				assert.Equal(t, int32(0), serviceIdentityCalls.Load())
				assert.Equal(t, int32(0), bootstrapCalls.Load())
			}
			assert.Equal(t, int32(1), refreshCalls.Load())
		})
	}
}
