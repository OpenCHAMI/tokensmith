// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	openchami_logger "github.com/openchami/chi-middleware/log"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog"
)

func isLoopbackRequest(r *http.Request) bool {
	host := r.RemoteAddr
	if socketPeer, ok := r.Context().Value(socketPeerContextKey).(string); ok && socketPeer != "" {
		host = socketPeer
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func preserveSocketPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), socketPeerContextKey, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *TokenService) requireLocalRequest(w http.ResponseWriter, r *http.Request) bool {
	if isLoopbackRequest(r) {
		return true
	}

	http.Error(w, "OIDC admin endpoints are local-only", http.StatusForbidden)
	return false
}

func (s *TokenService) withCurrentOIDCProvider(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := s.currentOIDCProvider()
		if provider == nil {
			http.Error(w, "OIDC provider is not configured", http.StatusServiceUnavailable)
			return
		}

		tokenValue, ok := r.Context().Value(oidc.TokenCtxKey{}).(string)
		if !ok {
			http.Error(w, "Invalid token in context", http.StatusUnauthorized)
			return
		}

		introspection, err := provider.IntrospectToken(r.Context(), tokenValue)
		if err != nil {
			logExchangeFailure(r, s.Config.OIDCClaimPolicy, http.StatusUnauthorized, exchangeFailureCategory(err), 0, false, err)
			http.Error(w, "Token introspection failed", http.StatusUnauthorized)
			return
		}
		if !introspection.Active {
			logExchangeFailure(r, s.Config.OIDCClaimPolicy, http.StatusUnauthorized, "inactive_token", 0, false, nil)
			http.Error(w, "Token is not active", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), oidc.IntrospectionCtxKey{}, introspection)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OIDCConfigStatusHandler returns the runtime single-provider OIDC status.
func (s *TokenService) OIDCConfigStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalRequest(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(OIDCConfigResponse{
		Status: "ok",
		OIDC:   s.GetOIDCProviderStatus(),
	})
}

// OIDCConfigHandler applies single-provider OIDC configuration updates in-process.
func (s *TokenService) OIDCConfigHandler(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalRequest(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req OIDCConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status, oidcStatus, err := s.ApplyOIDCProviderConfig(ctx, OIDCProviderConfigUpdate(req))
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "already configured") {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(OIDCConfigResponse{
		Status: status,
		OIDC:   oidcStatus,
	})
}

func (s *TokenService) newRouter(logger zerolog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(preserveSocketPeer)
	r.Use(openchami_logger.OpenCHAMILogger(logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.ClientIPFromRemoteAddr)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/health", s.HealthHandler)
	r.Route("/.well-known", func(r chi.Router) {
		r.Get("/jwks.json", s.JWKSHandler)
	})
	r.Route("/oauth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(oidc.RequireToken)
			r.Use(s.withCurrentOIDCProvider)
			r.Post("/exchange", s.TokenExchangeHandler)
		})
		r.Post("/revoke", s.RevokeTokenHandler)
	})
	r.Route("/admin/oidc", func(r chi.Router) {
		r.Get("/config", s.OIDCConfigStatusHandler)
		r.Post("/config", s.OIDCConfigHandler)
	})
	// RFC 8693 token endpoint for bootstrap and refresh token grants
	// See: https://datatracker.ietf.org/doc/html/rfc8693
	r.Post("/oauth/token", s.OAuthTokenHandler)
	r.Post("/token", s.OAuthTokenHandler) // Alias for compatibility
	r.Post("/service-identity/session", s.ServiceIdentitySessionHandler)

	return r
}
