// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSessionToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	tokenManager := token.NewTokenManager(keyManager, "test-issuer", "test-cluster", "test-openchami", true)

	service := &TokenService{
		TokenManager: tokenManager,
		Issuer:       "test-issuer",
		ClusterID:    "test-cluster",
		OpenCHAMIID:  "test-openchami",
		Config: Config{
			Issuer:      "test-issuer",
			ClusterID:   "test-cluster",
			OpenCHAMIID: "test-openchami",
		},
	}

	t.Run("Extract MFA claims from OIDC id_token", func(t *testing.T) {
		now := time.Now().Unix()

		claims := map[string]any{
			"sub":        "test-user",
			"email":      "user@example.com",
			"name":       "Test User",
			"amr":        []string{"pwd", "otp"},
			"acr":        "urn:okta:loa:2fa:any",
			"auth_time":  now,
			"session_id": "sess-test-123",
		}

		reqBody := SessionTokenRequest{
			LifetimeSeconds: 3600,
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		ctx := authn.ContextWithVerifiedClaims(req.Context(), claims)
		req = req.WithContext(ctx)

		resp := httptest.NewRecorder()

		service.CreateSessionToken(resp, req)

		assert.Equal(t, http.StatusCreated, resp.Code)

		var sessionResp SessionTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&sessionResp)
		require.NoError(t, err)

		assert.NotEmpty(t, sessionResp.JWT)
		assert.NotEmpty(t, sessionResp.TokenID)
		assert.NotEmpty(t, sessionResp.ExpiresAt)
		assert.Equal(t, "sess-test-123", sessionResp.SessionID)
		assert.Equal(t, []string{"pwd", "otp"}, sessionResp.AMR)
		assert.Equal(t, "urn:okta:loa:2fa:any", sessionResp.ACR)
		assert.Equal(t, now, sessionResp.AuthTime)

		parsedClaims, _, err := tokenManager.ParseToken(sessionResp.JWT)
		require.NoError(t, err)
		assert.Equal(t, "test-user", parsedClaims.Subject)
		assert.Equal(t, []string{"pwd", "otp"}, parsedClaims.AMR)
		assert.Equal(t, "urn:okta:loa:2fa:any", parsedClaims.ACR)
		assert.Equal(t, now, parsedClaims.AuthTime)
		assert.Equal(t, "sess-test-123", parsedClaims.SessionID)
	})

	t.Run("Use default lifetime when not specified", func(t *testing.T) {
		claims := map[string]any{
			"sub":   "test-user",
			"email": "user@example.com",
		}

		reqBody := SessionTokenRequest{}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		ctx := authn.ContextWithVerifiedClaims(req.Context(), claims)
		req = req.WithContext(ctx)

		resp := httptest.NewRecorder()

		service.CreateSessionToken(resp, req)

		assert.Equal(t, http.StatusCreated, resp.Code)

		var sessionResp SessionTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&sessionResp)
		require.NoError(t, err)

		parsedClaims, _, err := tokenManager.ParseToken(sessionResp.JWT)
		require.NoError(t, err)

		expiresAt := parsedClaims.ExpiresAt.Time
		issuedAt := parsedClaims.IssuedAt.Time
		lifetime := expiresAt.Sub(issuedAt)
		assert.Equal(t, DefaultSessionLifetime, lifetime)
	})

	t.Run("Reject lifetime exceeding maximum", func(t *testing.T) {
		claims := map[string]any{
			"sub":   "test-user",
			"email": "user@example.com",
		}

		reqBody := SessionTokenRequest{
			LifetimeSeconds: int64(MaxSessionLifetime.Seconds()) + 1,
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		ctx := authn.ContextWithVerifiedClaims(req.Context(), claims)
		req = req.WithContext(ctx)

		resp := httptest.NewRecorder()

		service.CreateSessionToken(resp, req)

		assert.Equal(t, http.StatusBadRequest, resp.Code)
		assert.Contains(t, resp.Body.String(), "exceeds maximum")
	})

	t.Run("Require authenticated context", func(t *testing.T) {
		reqBody := SessionTokenRequest{
			LifetimeSeconds: 3600,
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp := httptest.NewRecorder()

		service.CreateSessionToken(resp, req)

		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Contains(t, resp.Body.String(), "No verified claims")
	})

	t.Run("Require subject claim", func(t *testing.T) {
		claims := map[string]any{
			"email": "user@example.com",
		}

		reqBody := SessionTokenRequest{
			LifetimeSeconds: 3600,
		}
		bodyBytes, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		ctx := authn.ContextWithVerifiedClaims(context.Background(), claims)
		req = req.WithContext(ctx)

		resp := httptest.NewRecorder()

		service.CreateSessionToken(resp, req)

		assert.Equal(t, http.StatusBadRequest, resp.Code)
		assert.Contains(t, resp.Body.String(), "Missing 'sub' claim")
	})
}
