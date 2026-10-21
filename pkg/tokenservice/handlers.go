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
	"net/http"
	"os"
	"strings"

	"crypto/rsa"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
		logExchangeFailure(r, s.Config.OIDCClaimPolicy, http.StatusUnauthorized, exchangeFailureCategory(err), len(payload.Scope), payload.TargetService != "", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": tokenValue,
		"token_type":   "Bearer",
	})
}

// RevokeTokenHandler handles token revocation requests per RFC 7009.
// POST /oauth/revoke with parameter: token (required).
// token_type_hint is accepted but intentionally ignored.
// Per RFC 7009 Section 2.2, the endpoint MUST return 200 OK regardless of whether
// the token was valid, already revoked, or never existed (prevent token scanning).
func (s *TokenService) RevokeTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	tokenString := r.FormValue("token")
	if tokenString == "" {
		http.Error(w, "missing token parameter", http.StatusBadRequest)
		return
	}

	claims, _, err := s.TokenManager.ParseToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	if claims.ID != "" && claims.ExpiresAt != nil {
		s.revocationStore.Revoke(claims.ID, claims.ExpiresAt.Time)
	}

	w.WriteHeader(http.StatusOK)
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
