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
	"net"
	"net/http"
	"os"
	"sort"
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
	if parsedHost, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = parsedHost
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
			http.Error(w, "Token introspection failed", http.StatusUnauthorized)
			return
		}
		if !introspection.Active {
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

func (s *TokenService) issuerBaseURL() string {
	return strings.TrimRight(strings.TrimSpace(s.Issuer), "/")
}

func (s *TokenService) endpointURL(path string) string {
	base := s.issuerBaseURL()
	if base == "" {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}

func (s *TokenService) supportedScopes() []string {
	seen := make(map[string]struct{})
	for _, scopes := range s.GroupScopes {
		for _, scope := range scopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			seen[scope] = struct{}{}
		}
	}

	result := make([]string, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	sort.Strings(result)
	return result
}

func (s *TokenService) signingAlgorithmsSupported() []string {
	alg := strings.TrimSpace(s.TokenManager.GetSigningAlgorithm())
	if alg == "" {
		return []string{"RS256"}
	}
	return []string{alg}
}

func (s *TokenService) oauthManagementEndpointAuthMethodsSupported() []string {
	if s.Config.OAuthManagementAuthEnabled {
		return []string{"client_secret_basic"}
	}
	return []string{"none"}
}

// OAuthAuthorizationServerMetadataHandler publishes RFC 8414 metadata.
func (s *TokenService) OAuthAuthorizationServerMetadataHandler(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"issuer":                                s.issuerBaseURL(),
		"jwks_uri":                              s.endpointURL("/.well-known/jwks.json"),
		"token_endpoint":                        s.endpointURL("/oauth/token"),
		"introspection_endpoint":                s.endpointURL("/oauth/introspect"),
		"revocation_endpoint":                   s.endpointURL("/oauth/revoke"),
		"grant_types_supported":                 []string{GrantTypeTokenExchange, GrantTypeRefreshTokenRFC8693},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"introspection_endpoint_auth_methods_supported": s.oauthManagementEndpointAuthMethodsSupported(),
		"revocation_endpoint_auth_methods_supported":    s.oauthManagementEndpointAuthMethodsSupported(),
		"scopes_supported": s.supportedScopes(),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
}

// OpenIDConfigurationHandler publishes OpenID discovery metadata for non-interactive usage.
func (s *TokenService) OpenIDConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"issuer":                                s.issuerBaseURL(),
		"jwks_uri":                              s.endpointURL("/.well-known/jwks.json"),
		"token_endpoint":                        s.endpointURL("/oauth/token"),
		"introspection_endpoint":                s.endpointURL("/oauth/introspect"),
		"revocation_endpoint":                   s.endpointURL("/oauth/revoke"),
		"grant_types_supported":                 []string{GrantTypeTokenExchange, GrantTypeRefreshTokenRFC8693},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"introspection_endpoint_auth_methods_supported": s.oauthManagementEndpointAuthMethodsSupported(),
		"revocation_endpoint_auth_methods_supported":    s.oauthManagementEndpointAuthMethodsSupported(),
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         s.signingAlgorithmsSupported(),
		"scopes_supported":                              s.supportedScopes(),
		"openchami_non_interactive":                     true,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadata)
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
		r.Get("/oauth-authorization-server", s.OAuthAuthorizationServerMetadataHandler)
		r.Get("/openid-configuration", s.OpenIDConfigurationHandler)
	})
	r.Route("/oauth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(s.withOAuthManagementClientAuth)
			r.Post("/introspect", s.OAuthIntrospectionHandler)
			r.Post("/revoke", s.OAuthRevocationHandler)
		})
		r.Group(func(r chi.Router) {
			r.Use(oidc.RequireToken)
			r.Use(s.withCurrentOIDCProvider)
			r.Post("/token", s.TokenExchangeHandler)
			r.Get("/token", s.TokenExchangeHandler)
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

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server on %s\n", addr)
	return http.ListenAndServe(addr, r)
}
