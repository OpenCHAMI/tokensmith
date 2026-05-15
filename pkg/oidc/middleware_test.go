// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBearerToken_CaseInsensitiveScheme(t *testing.T) {
	token, ok := ParseBearerToken("bearer opaque-token")
	require.True(t, ok)
	assert.Equal(t, "opaque-token", token)
}

func TestRequireToken_AcceptsCaseInsensitiveBearerScheme(t *testing.T) {
	handler := RequireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenValue, _ := r.Context().Value(TokenCtxKey{}).(string)
		_, _ = w.Write([]byte(tokenValue))
	}))

	req := httptest.NewRequest(http.MethodGet, "/oidc/exchange", nil)
	req.Header.Set("Authorization", "bEaReR opaque-token")
	resp := httptest.NewRecorder()

	handler.ServeHTTP(resp, req)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "opaque-token", resp.Body.String())
}
