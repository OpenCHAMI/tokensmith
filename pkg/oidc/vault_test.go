// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVaultProviderValidatesJWTLocally(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var userInfoCalls int
	server := newVaultTestServer(t, &privateKey.PublicKey, func(w http.ResponseWriter, _ *http.Request) {
		userInfoCalls++
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	defer server.Close()

	now := time.Now()
	token := signVaultJWT(t, privateKey, server.URL, "vault-client", now.Add(time.Hour), jwt.SigningMethodRS256)
	provider := NewSimpleProvider(server.URL, "vault-client", "", WithProviderMode(ProviderModeVault))

	response, err := provider.IntrospectToken(context.Background(), token)
	require.NoError(t, err)
	assert.True(t, response.Active)
	assert.Equal(t, "entity-123", response.Username)
	assert.Equal(t, "Alice", response.Claims["name"])
	assert.Zero(t, userInfoCalls)
}

func TestVaultProviderRejectsInvalidJWTWithoutUserInfoFallback(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	server := newVaultTestServer(t, &privateKey.PublicKey, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "must not be called", http.StatusInternalServerError)
	})
	defer server.Close()

	tests := []struct {
		name   string
		issuer string
		aud    string
		exp    time.Time
		method jwt.SigningMethod
	}{
		{name: "wrong issuer", issuer: "https://other.example", aud: "vault-client", exp: time.Now().Add(time.Hour), method: jwt.SigningMethodRS256},
		{name: "wrong audience", issuer: server.URL, aud: "other-client", exp: time.Now().Add(time.Hour), method: jwt.SigningMethodRS256},
		{name: "expired", issuer: server.URL, aud: "vault-client", exp: time.Now().Add(-time.Hour), method: jwt.SigningMethodRS256},
		{name: "hmac is unsafe for jwks", issuer: server.URL, aud: "vault-client", exp: time.Now().Add(time.Hour), method: jwt.SigningMethodHS256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signVaultJWT(t, privateKey, tt.issuer, tt.aud, tt.exp, tt.method)
			provider := NewSimpleProvider(server.URL, "vault-client", "", WithProviderMode(ProviderModeVault))
			_, err := provider.IntrospectToken(context.Background(), token)
			require.Error(t, err)
		})
	}
}

func TestVaultProviderUsesUserInfoForOpaqueToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := newVaultTestServer(t, &privateKey.PublicKey, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer opaque-vault-token", r.Header.Get("Authorization"))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"sub": "entity-456", "name": "Vault User", "groups": []string{"ops", "admins"},
		}))
	})
	defer server.Close()

	before := time.Now()
	provider := NewSimpleProvider(server.URL, "vault-client", "",
		WithProviderMode(ProviderModeVault), WithVaultUserInfoFallbackTTL(2*time.Minute))
	response, err := provider.IntrospectToken(context.Background(), "opaque-vault-token")
	require.NoError(t, err)

	assert.True(t, response.Active)
	assert.Equal(t, "entity-456", response.Username)
	assert.Equal(t, "ops admins", response.Scope)
	assert.Equal(t, "Vault User", response.Claims["name"])
	assert.NotContains(t, response.Claims, "auth_level")
	assert.NotContains(t, response.Claims, "auth_factors")
	assert.NotContains(t, response.Claims, "auth_methods")
	assert.GreaterOrEqual(t, response.ExpiresAt, before.Add(119*time.Second).Unix())
	assert.LessOrEqual(t, response.ExpiresAt, time.Now().Add(2*time.Minute).Unix())
}

func TestVaultProviderRejectsInvalidUserInfo(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "missing subject", handler: func(w http.ResponseWriter, _ *http.Request) {
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"name": "No Subject"}))
		}},
		{name: "upstream rejection", handler: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "denied", http.StatusForbidden)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newVaultTestServer(t, &privateKey.PublicKey, tt.handler)
			defer server.Close()
			provider := NewSimpleProvider(server.URL, "vault-client", "", WithProviderMode(ProviderModeVault))
			_, err := provider.IntrospectToken(context.Background(), "opaque-token")
			require.Error(t, err)
		})
	}
}

func newVaultTestServer(t *testing.T, publicKey *rsa.PublicKey, userInfo http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"issuer": server.URL, "jwks_uri": server.URL + "/jwks", "userinfo_endpoint": server.URL + "/userinfo",
		}))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		e := big.NewInt(int64(publicKey.E)).Bytes()
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": "vault-key", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}}))
	})
	mux.HandleFunc("/userinfo", userInfo)
	return server
}

func signVaultJWT(t *testing.T, privateKey *rsa.PrivateKey, issuer, audience string, expiresAt time.Time, method jwt.SigningMethod) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": issuer, "aud": audience, "sub": "entity-123", "name": "Alice",
		"iat": time.Now().Add(-time.Minute).Unix(), "nbf": time.Now().Add(-time.Minute).Unix(), "exp": expiresAt.Unix(),
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = "vault-key"
	var key any = privateKey
	if strings.HasPrefix(method.Alg(), "HS") {
		key = []byte("attacker-secret")
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}
