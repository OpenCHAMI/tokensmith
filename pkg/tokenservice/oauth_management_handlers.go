// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	tokenTypeHintAccessToken  = "access_token"
	tokenTypeHintRefreshToken = "refresh_token"
)

type oauthIntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *TokenService) withOAuthManagementClientAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Config.OAuthManagementAuthEnabled {
			next.ServeHTTP(w, r)
			return
		}

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || !secureCompare(clientID, s.Config.OAuthManagementClientID) || !secureCompare(clientSecret, s.Config.OAuthManagementClientSecret) {
			w.Header().Set("WWW-Authenticate", `Basic realm="tokensmith-oauth-management"`)
			s.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *TokenService) writeIntrospectionResponse(w http.ResponseWriter, resp oauthIntrospectionResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// OAuthIntrospectionHandler implements RFC 7662 token introspection.
func (s *TokenService) OAuthIntrospectionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	tokenValue := strings.TrimSpace(r.FormValue("token"))
	if tokenValue == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing token parameter")
		return
	}

	tokenTypeHint := strings.TrimSpace(r.FormValue("token_type_hint"))
	if tokenTypeHint == "" {
		tokenTypeHint = tokenTypeHintAccessToken
	}

	if tokenTypeHint == tokenTypeHintRefreshToken {
		s.writeIntrospectionResponse(w, s.introspectRefreshToken(tokenValue))
		return
	}

	if tokenTypeHint != tokenTypeHintAccessToken {
		s.writeIntrospectionResponse(w, oauthIntrospectionResponse{Active: false})
		return
	}

	claims, _, err := s.TokenManager.ParseToken(tokenValue)
	if err != nil {
		s.writeIntrospectionResponse(w, oauthIntrospectionResponse{Active: false})
		return
	}

	resp := oauthIntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(claims.Scope, " "),
		ClientID:  claims.Subject,
		Username:  claims.Subject,
		TokenType: "Bearer",
		Sub:       claims.Subject,
		Aud:       strings.Join(claims.Audience, " "),
		Iss:       claims.Issuer,
		Jti:       claims.ID,
	}

	if claims.ExpiresAt != nil {
		resp.Exp = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		resp.Iat = claims.IssuedAt.Unix()
	}
	if claims.NotBefore != nil {
		resp.Nbf = claims.NotBefore.Unix()
	}

	s.writeIntrospectionResponse(w, resp)
}

func (s *TokenService) introspectRefreshToken(refreshToken string) oauthIntrospectionResponse {
	tokenHash := HashBootstrapToken(refreshToken)
	family, err := s.refreshTokenStore.GetFamilyByTokenHash(tokenHash)
	if err != nil {
		return oauthIntrospectionResponse{Active: false}
	}

	if family.IsRevoked() || family.IsExpired() || family.CurrentTokenHash != tokenHash {
		return oauthIntrospectionResponse{Active: false}
	}

	resp := oauthIntrospectionResponse{
		Active:    true,
		Scope:     strings.Join(family.Scopes, " "),
		ClientID:  family.Subject,
		Username:  family.Subject,
		TokenType: "refresh_token",
		Sub:       family.Subject,
		Aud:       family.Audience,
		Iss:       s.issuerBaseURL(),
	}

	if !family.ExpiresAt.IsZero() {
		resp.Exp = family.ExpiresAt.Unix()
	}
	if !family.IssuedAt.IsZero() {
		resp.Iat = family.IssuedAt.Unix()
	}

	return resp
}

// OAuthRevocationHandler implements RFC 7009 token revocation.
// TokenSmith supports revocation for opaque refresh tokens and token families.
func (s *TokenService) OAuthRevocationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	tokenValue := strings.TrimSpace(r.FormValue("token"))
	if tokenValue == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing token parameter")
		return
	}

	tokenTypeHint := strings.TrimSpace(r.FormValue("token_type_hint"))
	if tokenTypeHint == "" {
		tokenTypeHint = tokenTypeHintRefreshToken
	}

	if tokenTypeHint == tokenTypeHintAccessToken {
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_token_type", "Access token revocation is not supported")
		return
	}

	if tokenTypeHint != tokenTypeHintRefreshToken {
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_token_type", "Unsupported token_type_hint")
		return
	}

	tokenHash := HashBootstrapToken(tokenValue)
	family, err := s.refreshTokenStore.GetFamilyByTokenHash(tokenHash)
	if err == nil {
		now := time.Now()
		family.RevokedAt = &now
		_ = s.refreshTokenStore.UpdateFamily(family)
	}

	// RFC 7009 requires idempotent success semantics for unknown tokens.
	w.WriteHeader(http.StatusOK)
}
