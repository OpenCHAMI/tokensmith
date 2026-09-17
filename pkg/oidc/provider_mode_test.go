// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProviderMode(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    ProviderMode
		wantErr bool
	}{
		{name: "empty selects generic", value: "", want: ProviderModeGeneric},
		{name: "generic", value: "generic", want: ProviderModeGeneric},
		{name: "vault is case insensitive", value: " VaUlT ", want: ProviderModeVault},
		{name: "unknown mode", value: "other", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProviderMode(tt.value)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSimpleProviderDiscoveryRequirementsDependOnMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     ProviderMode
		metadata map[string]any
		wantErr  string
	}{
		{
			name: "generic requires introspection",
			mode: ProviderModeGeneric,
			metadata: map[string]any{
				"jwks_uri": "https://issuer.example/jwks",
			},
			wantErr: "introspection_endpoint",
		},
		{
			name: "vault requires userinfo",
			mode: ProviderModeVault,
			metadata: map[string]any{
				"jwks_uri": "https://issuer.example/jwks",
			},
			wantErr: "userinfo_endpoint",
		},
		{
			name: "vault does not require introspection",
			mode: ProviderModeVault,
			metadata: map[string]any{
				"jwks_uri":          "https://issuer.example/jwks",
				"userinfo_endpoint": "https://issuer.example/userinfo",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				metadata := make(map[string]any, len(tt.metadata)+1)
				maps.Copy(metadata, tt.metadata)
				metadata["issuer"] = server.URL
				require.NoError(t, json.NewEncoder(w).Encode(metadata))
			}))
			defer server.Close()

			provider := NewSimpleProvider(server.URL, "client", "", WithProviderMode(tt.mode))
			_, err := provider.GetProviderMetadata(context.Background())
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "provider metadata failure")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSimpleProviderGenericModeStillUsesIntrospection(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 server.URL,
				"introspection_endpoint": server.URL + "/introspect",
				"jwks_uri":               server.URL + "/jwks",
			}))
		case "/introspect":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, "opaque&token", r.Form.Get("token"))
			username, password, ok := r.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "client", username)
			assert.Equal(t, "secret", password)
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"active": true, "username": "generic-user", "claims": map[string]any{"iss": server.URL, "aud": "client"},
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := NewSimpleProvider(server.URL, "client", "secret")
	response, err := provider.IntrospectToken(context.Background(), "opaque&token")
	require.NoError(t, err)
	assert.True(t, response.Active)
	assert.Equal(t, "generic-user", response.Username)
}
