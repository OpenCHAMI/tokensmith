// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"bytes"
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

func TestSessionTokenLifecycle_Integration(t *testing.T) {
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
		sessionStore: NewSessionStore(),
		Config: Config{
			Issuer:      "test-issuer",
			ClusterID:   "test-cluster",
			OpenCHAMIID: "test-openchami",
		},
	}

	t.Run("Complete session lifecycle", func(t *testing.T) {
		now := time.Now().Unix()

		claims := map[string]any{
			"sub":        "test-user@example.com",
			"email":      "test-user@example.com",
			"name":       "Test User",
			"amr":        []string{"pwd", "otp"},
			"acr":        "urn:okta:loa:2fa:any",
			"auth_time":  now,
			"session_id": "sess-lifecycle-test",
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

		require.Equal(t, http.StatusCreated, resp.Code)

		var sessionResp SessionTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&sessionResp)
		require.NoError(t, err)

		assert.NotEmpty(t, sessionResp.JWT)
		sessionJWT := sessionResp.JWT
		tokenID := sessionResp.TokenID
		sessionID := sessionResp.SessionID

		t.Log("Step 1: Session created successfully")

		storedSession, ok := service.sessionStore.GetSessionByID(sessionID)
		require.True(t, ok, "Session should be stored")
		assert.Equal(t, tokenID, storedSession.TokenID)
		assert.Equal(t, "test-user@example.com", storedSession.Subject)
		assert.False(t, storedSession.Revoked)

		t.Log("Step 2: Session stored correctly in session store")

		parsedClaims, _, err := tokenManager.ParseToken(sessionJWT)
		require.NoError(t, err)
		assert.Equal(t, "test-user@example.com", parsedClaims.Subject)
		assert.Equal(t, []string{"pwd", "otp"}, parsedClaims.AMR)
		assert.Equal(t, "urn:okta:loa:2fa:any", parsedClaims.ACR)
		assert.Equal(t, now, parsedClaims.AuthTime)
		assert.Equal(t, sessionID, parsedClaims.SessionID)

		t.Log("Step 3: JWT contains correct MFA claims")

		assert.False(t, service.sessionStore.IsRevoked(sessionID))

		t.Log("Step 4: Session is not revoked")

		err = service.sessionStore.RevokeSession(sessionID)
		require.NoError(t, err)

		t.Log("Step 5: Session revoked successfully")

		assert.True(t, service.sessionStore.IsRevoked(sessionID))

		revokedSession, ok := service.sessionStore.GetSessionByID(sessionID)
		require.True(t, ok)
		assert.True(t, revokedSession.Revoked)
		assert.NotNil(t, revokedSession.RevokedAt)

		t.Log("Step 6: Revocation persisted in session store")
	})

	t.Run("Multiple sessions for same user", func(t *testing.T) {
		now := time.Now().Unix()
		subject := "multi-session-user@example.com"

		claims := map[string]any{
			"sub":       subject,
			"email":     subject,
			"name":      "Multi Session User",
			"amr":       []string{"pwd", "otp"},
			"acr":       "urn:okta:loa:2fa:any",
			"auth_time": now,
		}

		var sessionIDs []string

		for i := 0; i < 3; i++ {
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

			require.Equal(t, http.StatusCreated, resp.Code)

			var sessionResp SessionTokenResponse
			err = json.NewDecoder(resp.Body).Decode(&sessionResp)
			require.NoError(t, err)

			sessionIDs = append(sessionIDs, sessionResp.SessionID)
		}

		userSessions := service.sessionStore.ListUserSessions(subject)
		assert.GreaterOrEqual(t, len(userSessions), 3, "User should have at least 3 sessions")

		for _, sessionID := range sessionIDs {
			found := false
			for _, session := range userSessions {
				if session.SessionID == sessionID {
					found = true
					assert.Equal(t, subject, session.Subject)
					break
				}
			}
			assert.True(t, found, "Session %s should be in user's session list", sessionID)
		}
	})

	t.Run("Session with parent token inheritance", func(t *testing.T) {
		now := time.Now().Unix()

		parentClaims := map[string]any{
			"sub":        "parent-user@example.com",
			"email":      "parent-user@example.com",
			"amr":        []string{"pwd", "fido2"},
			"acr":        "urn:okta:loa:fido2",
			"auth_time":  now - 100,
			"session_id": "parent-session",
		}

		parentReqBody := SessionTokenRequest{
			LifetimeSeconds: 7200,
		}
		bodyBytes, err := json.Marshal(parentReqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		ctx := authn.ContextWithVerifiedClaims(req.Context(), parentClaims)
		req = req.WithContext(ctx)

		resp := httptest.NewRecorder()
		service.CreateSessionToken(resp, req)

		require.Equal(t, http.StatusCreated, resp.Code)

		var parentResp SessionTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&parentResp)
		require.NoError(t, err)

		childClaims := map[string]any{
			"sub":   "parent-user@example.com",
			"email": "parent-user@example.com",
		}

		childReqBody := SessionTokenRequest{
			LifetimeSeconds: 3600,
			ParentTokenID:   parentResp.TokenID,
		}
		bodyBytes, err = json.Marshal(childReqBody)
		require.NoError(t, err)

		childReq := httptest.NewRequest(http.MethodPost, "/oauth/session", bytes.NewReader(bodyBytes))
		childReq.Header.Set("Content-Type", "application/json")

		childCtx := authn.ContextWithVerifiedClaims(childReq.Context(), childClaims)
		childReq = childReq.WithContext(childCtx)

		childResp := httptest.NewRecorder()
		service.CreateSessionToken(childResp, childReq)

		require.Equal(t, http.StatusCreated, childResp.Code)

		var childSessionResp SessionTokenResponse
		err = json.NewDecoder(childResp.Body).Decode(&childSessionResp)
		require.NoError(t, err)

		parsedChildClaims, _, err := tokenManager.ParseToken(childSessionResp.JWT)
		require.NoError(t, err)

		assert.Equal(t, parentResp.TokenID, parsedChildClaims.ParentID, "Child token should reference parent token")
	})

	t.Run("Expired session cleanup", func(t *testing.T) {
		now := time.Now()

		expiredSession := &SessionToken{
			SessionID: "expired-session",
			TokenID:   "expired-token",
			Subject:   "expired@example.com",
			CreatedAt: now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-1 * time.Hour),
			Revoked:   false,
		}

		activeSession := &SessionToken{
			SessionID: "active-session",
			TokenID:   "active-token",
			Subject:   "active@example.com",
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
			Revoked:   false,
		}

		require.NoError(t, service.sessionStore.SaveSession(expiredSession))
		require.NoError(t, service.sessionStore.SaveSession(activeSession))

		_, ok := service.sessionStore.GetSessionByID("expired-session")
		require.True(t, ok, "Expired session should exist before cleanup")

		removed := service.sessionStore.CleanupExpired()
		assert.Equal(t, 1, removed, "Should remove exactly one expired session")

		_, ok = service.sessionStore.GetSessionByID("expired-session")
		assert.False(t, ok, "Expired session should be removed after cleanup")

		_, ok = service.sessionStore.GetSessionByID("active-session")
		assert.True(t, ok, "Active session should remain after cleanup")
	})
}
