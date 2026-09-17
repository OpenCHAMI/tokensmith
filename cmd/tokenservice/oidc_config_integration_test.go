// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	os.Stdout = orig

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

func TestOIDCConfigureCLI_ReplaceProtection(t *testing.T) {
	existing := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oidc/config" {
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "ok",
				"oidc": map[string]any{
					"configured":              existing,
					"issuer_url":              "https://issuer.example",
					"client_id":               "client-id",
					"local_user_mint_enabled": false,
				},
			})
		case http.MethodPost:
			var payload struct {
				ReplaceExisting bool   `json:"replace_existing"`
				ClaimPolicy     string `json:"claim_policy"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "bad payload", http.StatusBadRequest)
				return
			}

			if existing && !payload.ReplaceExisting {
				http.Error(w, "OIDC provider already configured; use --replace-existing to overwrite", http.StatusConflict)
				return
			}

			status := "created"
			if existing {
				status = "replaced"
			}
			existing = true

			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": status,
				"oidc": map[string]any{
					"configured":              true,
					"issuer_url":              "https://issuer.example",
					"client_id":               "client-id",
					"claim_policy":            payload.ClaimPolicy,
					"local_user_mint_enabled": false,
				},
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	rootCmd.SetArgs([]string{
		"oidc", "configure",
		"--url", server.URL,
		"--issuer-url", "https://issuer-a.example",
		"--client-id", "client-a",
	})
	require.NoError(t, rootCmd.Execute())

	rootCmd.SetArgs([]string{
		"oidc", "configure",
		"--url", server.URL,
		"--issuer-url", "https://issuer-b.example",
		"--client-id", "client-b",
	})
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "409") || strings.Contains(err.Error(), "already configured"), fmt.Sprintf("unexpected error: %v", err))

	rootCmd.SetArgs([]string{
		"oidc", "configure",
		"--url", server.URL,
		"--issuer-url", "https://issuer-b.example",
		"--client-id", "client-b",
		"--claim-policy", "csm-keycloak",
		"--replace-existing",
	})
	require.NoError(t, rootCmd.Execute())
}

func TestOIDCStatusCLI_ReportsLocalUserMintEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/oidc/config" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"oidc": map[string]any{
				"configured":              true,
				"issuer_url":              "https://issuer.example",
				"client_id":               "client-id",
				"claim_policy":            "csm-keycloak",
				"local_user_mint_enabled": true,
			},
		})
	}))
	defer server.Close()

	output := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"oidc", "status", "--url", server.URL})
		require.NoError(t, rootCmd.Execute())
	})

	assert.Contains(t, output, "Configured: true")
	assert.Contains(t, output, "Issuer URL: https://issuer.example")
	assert.Contains(t, output, "Client ID: client-id")
	assert.Contains(t, output, "Claim Policy: csm-keycloak")
	assert.Contains(t, output, "Local User Mint Enabled: true")
}

func TestOIDCConfigureCLI_SendsVaultSettings(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"status": "created",
			"oidc": map[string]any{
				"configured": true, "issuer_url": "https://vault.example", "client_id": "vault-client", "provider_mode": "vault",
			},
		}))
	}))
	defer server.Close()

	rootCmd.SetArgs([]string{
		"oidc", "configure", "--url", server.URL,
		"--issuer-url", "https://vault.example", "--client-id", "vault-client",
		"--provider-mode", "vault", "--vault-userinfo-fallback-ttl", "2m",
	})
	require.NoError(t, rootCmd.Execute())
	assert.Equal(t, "vault", payload["provider_mode"])
	assert.Equal(t, float64(120), payload["vault_userinfo_fallback_ttl_seconds"])
}
