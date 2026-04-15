// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestTokenService(t *testing.T, cfg Config) *TokenService {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	svc, err := NewTokenService(keyManager, cfg)
	require.NoError(t, err)
	return svc
}

func newDiscoveryServer() *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 server.URL,
			"introspection_endpoint": server.URL + "/introspect",
			"jwks_uri":               server.URL + "/jwks",
			"scopes_supported":       []string{"read", "write"},
		})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": true})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})

	return server
}

func TestApplyOIDCProviderConfig_CreateAndReplaceProtection(t *testing.T) {
	discovery := newDiscoveryServer()
	defer discovery.Close()

	svc := newTestTokenService(t, Config{
		Issuer:           "test-issuer",
		ClusterID:        "cl-test",
		OpenCHAMIID:      "oc-test",
		OIDCClientSecret: "secret-from-env",
	})

	status, state, err := svc.ApplyOIDCProviderConfig(context.Background(), OIDCProviderConfigUpdate{
		IssuerURL: discovery.URL,
		ClientID:  "client-a",
	})
	require.NoError(t, err)
	assert.Equal(t, "created", status)
	assert.True(t, state.Configured)
	assert.Equal(t, discovery.URL, state.IssuerURL)
	assert.Equal(t, "client-a", state.ClientID)

	_, _, err = svc.ApplyOIDCProviderConfig(context.Background(), OIDCProviderConfigUpdate{
		IssuerURL: discovery.URL,
		ClientID:  "client-b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already configured")
}

func TestApplyOIDCProviderConfig_DryRunDoesNotMutate(t *testing.T) {
	discovery := newDiscoveryServer()
	defer discovery.Close()

	svc := newTestTokenService(t, Config{
		Issuer:           "test-issuer",
		ClusterID:        "cl-test",
		OpenCHAMIID:      "oc-test",
		OIDCIssuerURL:    "http://existing-issuer",
		OIDCClientID:     "existing-client",
		OIDCClientSecret: "secret-from-env",
	})

	status, _, err := svc.ApplyOIDCProviderConfig(context.Background(), OIDCProviderConfigUpdate{
		IssuerURL:       discovery.URL,
		ClientID:        "new-client",
		ReplaceExisting: true,
		DryRun:          true,
	})
	require.NoError(t, err)
	assert.Equal(t, "would_replace", status)

	state := svc.GetOIDCProviderStatus()
	assert.Equal(t, "http://existing-issuer", state.IssuerURL)
	assert.Equal(t, "existing-client", state.ClientID)
}

func TestOIDCConfigHandler_LocalOnly(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:           "test-issuer",
		ClusterID:        "cl-test",
		OpenCHAMIID:      "oc-test",
		OIDCClientSecret: "secret-from-env",
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/oidc/config", nil)
	req.RemoteAddr = "10.0.0.1:41234"
	resp := httptest.NewRecorder()

	svc.OIDCConfigStatusHandler(resp, req)
	assert.Equal(t, http.StatusForbidden, resp.Code)
}

func TestGetOIDCProviderStatus_ReflectsLocalUserMintEnabled(t *testing.T) {
	svc := newTestTokenService(t, Config{
		Issuer:              "test-issuer",
		ClusterID:           "cl-test",
		OpenCHAMIID:         "oc-test",
		OIDCIssuerURL:       "https://issuer.example",
		OIDCClientID:        "client-id",
		OIDCClientSecret:    "secret-from-env",
		EnableLocalUserMint: true,
	})

	status := svc.GetOIDCProviderStatus()
	assert.True(t, status.Configured)
	assert.Equal(t, "https://issuer.example", status.IssuerURL)
	assert.Equal(t, "client-id", status.ClientID)
	assert.True(t, status.LocalUserMintEnabled)
}
