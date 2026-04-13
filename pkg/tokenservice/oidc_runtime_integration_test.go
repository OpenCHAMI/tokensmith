// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newOIDCTestProviderServer(username string) *httptest.Server {
	now := time.Now().Unix()

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
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":     true,
			"username":   username,
			"exp":        now + 3600,
			"iat":        now,
			"token_type": "Bearer",
			"claims": map[string]interface{}{
				"aud":          []string{"svc-target"},
				"groups":       []string{"viewer"},
				"auth_level":   "IAL2",
				"auth_factors": 2,
				"auth_methods": []string{"password", "mfa"},
				"session_id":   "sid-" + username,
				"session_exp":  now + 3600,
				"auth_events":  []string{"login"},
			},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})

	return server
}

func applyOIDCConfigViaHandler(t *testing.T, svc *TokenService, reqBody map[string]interface{}) int {
	t.Helper()

	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/admin/oidc/config", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:41234"
	resp := httptest.NewRecorder()

	svc.OIDCConfigHandler(resp, req)
	return resp.Code
}

func TestOIDCRuntimeReplaceIntegration_UpdatesExchangeBehavior(t *testing.T) {
	providerA := newOIDCTestProviderServer("user-a")
	defer providerA.Close()

	providerB := newOIDCTestProviderServer("user-b")
	defer providerB.Close()

	svc := newTestTokenService(t, Config{
		Issuer:           "tokensmith-test",
		ClusterID:        "cl-test",
		OpenCHAMIID:      "oc-test",
		OIDCClientSecret: "secret-from-env",
		GroupScopes: map[string][]string{
			"viewer": {"read"},
		},
	})

	status := applyOIDCConfigViaHandler(t, svc, map[string]interface{}{
		"issuer_url": providerA.URL,
		"client_id":  "client-a",
	})
	require.Equal(t, http.StatusOK, status)

	tokA, err := svc.ExchangeToken(context.Background(), "opaque-token-a")
	require.NoError(t, err)
	claimsA, _, err := svc.TokenManager.ParseToken(tokA)
	require.NoError(t, err)
	assert.Equal(t, "user-a", claimsA.Subject)

	status = applyOIDCConfigViaHandler(t, svc, map[string]interface{}{
		"issuer_url": providerB.URL,
		"client_id":  "client-b",
	})
	require.Equal(t, http.StatusConflict, status)

	status = applyOIDCConfigViaHandler(t, svc, map[string]interface{}{
		"issuer_url":       providerB.URL,
		"client_id":        "client-b",
		"replace_existing": true,
	})
	require.Equal(t, http.StatusOK, status)

	tokB, err := svc.ExchangeToken(context.Background(), "opaque-token-b")
	require.NoError(t, err)
	claimsB, _, err := svc.TokenManager.ParseToken(tokB)
	require.NoError(t, err)
	assert.Equal(t, "user-b", claimsB.Subject)
}
