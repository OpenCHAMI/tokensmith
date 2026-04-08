// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/rsa"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	openchami_logger "github.com/openchami/chi-middleware/log"
)

// JWKSHandler handles JWKS requests.
func (s *TokenService) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	publicKeyInterface, err := s.TokenManager.GetKeyManager().GetPublicKey()
	if err != nil {
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		http.Error(w, "Public key is not an RSA key", http.StatusInternalServerError)
		return
	}

	kid, err := s.TokenManager.GetKeyManager().GetKid()
	if err != nil {
		http.Error(w, "kid is not set", http.StatusInternalServerError)
		return
	}

	alg := s.TokenManager.GetSigningAlgorithm()
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": alg,
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
		return
	}
}

// TokenExchangeHandler handles token exchange requests.
func (s *TokenService) TokenExchangeHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	var payload struct {
		Scope         []string `json:"scope"`
		TargetService string   `json:"target_service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctx := context.WithValue(r.Context(), ScopeContextKey, payload.Scope)
	ctx = context.WithValue(ctx, TargetServiceContextKey, payload.TargetService)

	tokenValue, err := s.ExchangeToken(ctx, parts[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": tokenValue,
		"token_type":   "Bearer",
	})
}

// HealthHandler provides a health check endpoint.
func (s *TokenService) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "healthy",
		"service":      "tokensmith",
		"issuer":       s.Issuer,
		"cluster_id":   s.ClusterID,
		"openchami_id": s.OpenCHAMIID,
		"oidc_issuer":  s.Config.OIDCIssuerURL,
	})
}

// Start starts the HTTP server.
func (s *TokenService) Start(port int) error {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	r := chi.NewRouter()
	r.Use(openchami_logger.OpenCHAMILogger(logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
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
			r.Use(oidc.RequireValidToken(s.OIDCProvider))
			r.Post("/token", s.TokenExchangeHandler)
			r.Get("/token", s.TokenExchangeHandler)
		})
	})
	// RFC 8693 token endpoint for bootstrap and refresh token grants
	// See: https://datatracker.ietf.org/doc/html/rfc8693
	r.Post("/oauth/token", s.OAuthTokenHandler)
	r.Post("/token", s.OAuthTokenHandler) // Alias for compatibility

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server on %s\n", addr)
	return http.ListenAndServe(addr, r)
}
