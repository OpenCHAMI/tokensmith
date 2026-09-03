// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
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
			// Report what actually failed. Every validation failure previously
			// surfaced as "Token introspection failed", including ones where
			// introspection never ran -- a local signature failure, an expired
			// token and a provider outage were indistinguishable to the caller,
			// which makes misconfiguration expensive to diagnose. The status
			// code is unchanged.
			logExchangeFailure(r, s.Config.OIDCClaimPolicy, http.StatusUnauthorized, exchangeFailureCategory(err), 0, false, err)
			http.Error(w, tokenValidationMessage(err), http.StatusUnauthorized)
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

// tokenValidationMessage describes a validation failure without disclosing
// anything about the token itself.
func tokenValidationMessage(err error) string {
	switch {
	case errors.Is(err, oidc.ErrUpstreamUnavailable):
		return "Identity provider is unavailable"
	case errors.Is(err, oidc.ErrProviderMetadata):
		return "Cannot load identity provider metadata or signing keys"
	case errors.Is(err, oidc.ErrUpstreamRejected):
		return "Identity provider rejected the token"
	case errors.Is(err, oidc.ErrInvalidResponse):
		return "Identity provider returned an unreadable response"
	case errors.Is(err, oidc.ErrInvalidToken):
		return "Token is not valid for this identity provider"
	default:
		return "Token validation failed"
	}
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

// TokenExchangeHandler handles token exchange requests.
func (s *TokenService) TokenExchangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	token, ok := oidc.ParseBearerToken(authHeader)
	if !ok {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	var payload struct {
		Scope         []string `json:"scope"`
		TargetService string   `json:"target_service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx := context.WithValue(r.Context(), ScopeContextKey, payload.Scope)
	ctx = context.WithValue(ctx, TargetServiceContextKey, payload.TargetService)

	tokenValue, err := s.ExchangeToken(ctx, token)
	if err != nil {
		// Distinguish "we do not know who you are" from "we know exactly who you
		// are and you may not do this". Answering 401 to an authorization
		// failure invites the client to discard a valid session and
		// re-authenticate, which cannot help and loops.
		status := http.StatusUnauthorized
		if errors.Is(err, ErrExchangeNoAuthorizedGroups) {
			status = http.StatusForbidden
		}
		logExchangeFailure(r, s.Config.OIDCClaimPolicy, status, exchangeFailureCategory(err), len(payload.Scope), payload.TargetService != "", err)
		http.Error(w, err.Error(), status)
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
		"status":                         "healthy",
		"service":                        "tokensmith",
		"issuer":                         s.Issuer,
		"cluster_id":                     s.ClusterID,
		"openchami_id":                   s.OpenCHAMIID,
		"oidc_issuer":                    s.Config.OIDCIssuerURL,
		"service_identity_ca_configured": s.serviceIdentityCAPool != nil,
	})
}

func (s *TokenService) newRouter(logger zerolog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(preserveSocketPeer)
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
			r.Use(s.withCurrentOIDCProvider)
			r.Post("/exchange", s.TokenExchangeHandler)
		})
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

// Start starts the HTTP server.
func (s *TokenService) Start(port int) error {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:    addr,
		Handler: s.newRouter(logger),
	}

	tlsCert := strings.TrimSpace(s.Config.TLSCertFile)
	tlsKey := strings.TrimSpace(s.Config.TLSKeyFile)

	switch {
	case (tlsCert == "") != (tlsKey == ""):
		return fmt.Errorf("both TLS server cert and key must be provided together")
	case tlsCert != "" && tlsKey != "":
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if s.serviceIdentityCAPool != nil {
			server.TLSConfig.ClientAuth = tls.VerifyClientCertIfGiven
			server.TLSConfig.ClientCAs = s.serviceIdentityCAPool
		}

		fmt.Printf("Starting TLS server on %s\n", addr)
		return server.ListenAndServeTLS(tlsCert, tlsKey)
	default:
		if s.serviceIdentityCAPool != nil {
			return fmt.Errorf("service identity CA is configured via --service-identity-ca or TOKENSMITH_SERVICE_IDENTITY_CA, but TLS server cert/key are not; inbound service identity mTLS requires --tls-cert-file and --tls-key-file; use --oidc-ca only for outbound upstream OIDC TLS")
		}
		fmt.Printf("Starting server on %s\n", addr)
		return server.ListenAndServe()
	}
}
