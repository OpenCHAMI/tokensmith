// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevokeTokenHandler_RFC7009Compliance(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	tokenManager := token.NewTokenManager(keyManager, "test-issuer", "test-cluster", "test-openchami", false)

	service := &TokenService{
		TokenManager:    tokenManager,
		revocationStore: NewRevocationStore(),
	}

	t.Run("RFC 7009 Section 2.2: Returns 200 OK for valid token", func(t *testing.T) {
		claims := token.NewClaims()
		claims.Subject = "test-user"
		claims.Issuer = "test-issuer"
		claims.Audience = []string{"test-audience"}

		validToken, err := tokenManager.GenerateToken(claims)
		require.NoError(t, err)

		form := url.Values{}
		form.Set("token", validToken)

		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		service.RevokeTokenHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK")

		parsedClaims, _, err := tokenManager.ParseToken(validToken)
		require.NoError(t, err)
		assert.True(t, service.revocationStore.IsRevoked(parsedClaims.ID), "Token JTI should be revoked")
	})

	t.Run("RFC 7009 Section 2.2: Returns 200 OK for invalid token", func(t *testing.T) {
		form := url.Values{}
		form.Set("token", "invalid-token")

		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		service.RevokeTokenHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Should return 200 OK even for invalid token")
	})

	t.Run("RFC 7009 Section 2.2: Returns 200 OK for already revoked token", func(t *testing.T) {
		claims := token.NewClaims()
		claims.Subject = "test-user"
		claims.Issuer = "test-issuer"
		claims.Audience = []string{"test-audience"}

		validToken, err := tokenManager.GenerateToken(claims)
		require.NoError(t, err)

		form := url.Values{}
		form.Set("token", validToken)

		req1 := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w1 := httptest.NewRecorder()
		service.RevokeTokenHandler(w1, req1)
		assert.Equal(t, http.StatusOK, w1.Code)

		req2 := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w2 := httptest.NewRecorder()
		service.RevokeTokenHandler(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code, "Should return 200 OK for already revoked token")
	})

	t.Run("Returns 400 for missing token parameter", func(t *testing.T) {
		form := url.Values{}

		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		service.RevokeTokenHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "Should return 400 for missing token")
	})

	t.Run("Returns 405 for non-POST methods", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/revoke", nil)
		w := httptest.NewRecorder()

		service.RevokeTokenHandler(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code, "Should return 405 for GET")
	})

	t.Run("Revoked token remains revoked until expiry", func(t *testing.T) {
		claims := token.NewClaims()
		claims.Subject = "test-user"
		claims.Issuer = "test-issuer"
		claims.Audience = []string{"test-audience"}
		claims.ExpiresAt.Time = time.Now().Add(1 * time.Hour)

		validToken, err := tokenManager.GenerateToken(claims)
		require.NoError(t, err)

		form := url.Values{}
		form.Set("token", validToken)

		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		service.RevokeTokenHandler(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		parsedClaims, _, err := tokenManager.ParseToken(validToken)
		require.NoError(t, err)

		assert.True(t, service.revocationStore.IsRevoked(parsedClaims.ID), "Token should remain revoked")

		time.Sleep(10 * time.Millisecond)
		assert.True(t, service.revocationStore.IsRevoked(parsedClaims.ID), "Token should still be revoked")
	})
}
