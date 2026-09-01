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

func newOIDCTestProviderServer(username string, clientID string) *httptest.Server {
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
				"iss":          server.URL,
				"aud":          []string{"svc-target"},
				"azp":          clientID,
				"client_id":    clientID,
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
	providerA := newOIDCTestProviderServer("user-a", "client-a")
	defer providerA.Close()

	providerB := newOIDCTestProviderServer("user-b", "client-b")
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

func TestExchangeToken_WithKeycloakTopLevelIntrospectionClaims(t *testing.T) {
	provider := newKeycloakTopLevelIntrospectionServer(t)
	defer provider.Close()

	svc := newTestTokenService(t, Config{
		Issuer:           "tokensmith-test",
		ClusterID:        "cl-test",
		OpenCHAMIID:      "oc-test",
		OIDCIssuerURL:    provider.URL,
		OIDCClientID:     "tokensmith",
		OIDCClientSecret: "secret-from-env",
		OIDCClaimPolicy:  OIDCClaimPolicyCSMKeycloak,
		GroupScopes: map[string][]string{
			"admin": {"read", "write"},
		},
	})
	ctx := context.WithValue(context.Background(), ScopeContextKey, []string{"read"})

	tokenValue, err := svc.ExchangeToken(ctx, "opaque-token")

	require.NoError(t, err)
	claims, _, err := svc.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "keycloak-admin", claims.Subject)
	assert.Equal(t, []string{"tokensmith"}, []string(claims.Audience))
	assert.Equal(t, []string{"read"}, claims.Scope)
	assert.Equal(t, "IAL2", claims.AuthLevel)
	assert.Equal(t, 2, claims.AuthFactors)
	assert.ElementsMatch(t, []string{"password", "otp"}, claims.AuthMethods)
	assert.Equal(t, "keycloak-session-1", claims.SessionID)
}

func TestExchangeToken_WithObservedKeycloakServiceAccountShape(t *testing.T) {
	provider := newObservedKeycloakServiceAccountServer(t)
	defer provider.Close()

	svc := newTestTokenService(t, Config{
		Issuer:           "tokensmith-test",
		ClusterID:        "cl-test",
		OpenCHAMIID:      "oc-test",
		OIDCIssuerURL:    provider.URL,
		OIDCClientID:     "openchami-tokensmith",
		OIDCClientSecret: "secret-from-env",
		OIDCClaimPolicy:  OIDCClaimPolicyCSMKeycloak,
	})

	tokenValue, err := svc.ExchangeToken(context.Background(), "opaque-token")

	require.NoError(t, err)
	claims, _, err := svc.TokenManager.ParseToken(tokenValue)
	require.NoError(t, err)
	assert.Equal(t, "service-account-openchami-tokensmith", claims.Subject)
	assert.Equal(t, []string{"account"}, []string(claims.Audience))
	assert.Empty(t, claims.Scope)
	assert.Equal(t, "1", claims.AuthLevel)
	assert.Equal(t, 2, claims.AuthFactors)
	assert.Equal(t, []string{"keycloak", "client_credentials"}, claims.AuthMethods)
	assert.Equal(t, "7836e8d0-6928-4db8-90ee-dea5a7888dc7", claims.SessionID)
	assert.Equal(t, []string{"token_exchange"}, claims.AuthEvents)
}

func newKeycloakTopLevelIntrospectionServer(t *testing.T) *httptest.Server {
	t.Helper()
	now := time.Now().Unix()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                       server.URL,
			"token_introspection_endpoint": server.URL + "/token/introspect",
			"jwks_uri":                     server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":      true,
			"sub":         "keycloak-admin",
			"iss":         server.URL,
			"aud":         "tokensmith",
			"groups":      []string{"admin"},
			"acr":         "IAL2",
			"amr":         []string{"pwd", "otp"},
			"sid":         "keycloak-session-1",
			"auth_events": []string{"login"},
			"exp":         now + 3600,
			"iat":         now,
			"token_type":  "Bearer",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})
	return server
}

func newObservedKeycloakServiceAccountServer(t *testing.T) *httptest.Server {
	t.Helper()
	now := time.Now().Unix()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                       server.URL,
			"token_introspection_endpoint": server.URL + "/token/introspect",
			"jwks_uri":                     server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"active":             true,
			"exp":                now + 300,
			"iat":                now,
			"jti":                "7836e8d0-6928-4db8-90ee-dea5a7888dc7",
			"iss":                server.URL,
			"aud":                "account",
			"sub":                "5eca73ee-c3f3-4a0c-a5ef-e1f25ed764a4",
			"typ":                "Bearer",
			"azp":                "openchami-tokensmith",
			"acr":                "1",
			"scope":              "email offline_access openid profile",
			"email_verified":     false,
			"preferred_username": "service-account-openchami-tokensmith",
			"client_id":          "openchami-tokensmith",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})
	return server
}
