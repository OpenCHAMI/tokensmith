// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crypto/rsa"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	openchami_logger "github.com/openchami/chi-middleware/log"
)

type contextKey string

const (
	ScopeContextKey         contextKey = "scope"
	TargetServiceContextKey contextKey = "target_service"
)

// Config holds the configuration for the token service
type Config struct {
	Issuer                string
	GroupScopes           map[string][]string
	ClusterID             string
	OpenCHAMIID           string
	NonEnforcing          bool // Skip validation checks and only log errors
	BootstrapJTIStorePath string

	// OIDC provider configuration
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
}

// TokenService handles token operations and provider interactions
type TokenService struct {
	TokenManager *token.TokenManager
	Config       Config
	Issuer       string
	GroupScopes  map[string][]string
	ClusterID    string
	OpenCHAMIID  string
	OIDCProvider oidc.Provider
	mu           sync.RWMutex
	bootstrapMu  sync.Mutex
	usedBootJTI  map[string]time.Time
}

// NewTokenService creates a new TokenService instance
func NewTokenService(keyManager *keys.KeyManager, config Config) (*TokenService, error) {
	// Initialize the token manager
	tokenManager := token.NewTokenManager(
		keyManager,
		config.Issuer,
		config.ClusterID,
		config.OpenCHAMIID,
		!config.NonEnforcing, // Enforce claims validation
	)

	// Initialize the simplified OIDC provider
	oidcProvider := oidc.NewSimpleProvider(
		config.OIDCIssuerURL,
		config.OIDCClientID,
		config.OIDCClientSecret,
	)

	svc := &TokenService{
		TokenManager: tokenManager,
		Config:       config,
		Issuer:       config.Issuer,
		GroupScopes:  config.GroupScopes,
		ClusterID:    config.ClusterID,
		OpenCHAMIID:  config.OpenCHAMIID,
		OIDCProvider: oidcProvider,
		usedBootJTI:  map[string]time.Time{},
	}

	if err := svc.loadBootstrapJTIStore(); err != nil {
		return nil, fmt.Errorf("failed to load bootstrap jti store: %w", err)
	}

	return svc, nil
}

// MintBootstrapToken creates a short-lived bootstrap token intended for one-time
// exchange at /service/token to obtain a standard service token.
func (s *TokenService) MintBootstrapToken(ctx context.Context, serviceID, targetService string, scopes []string, ttl time.Duration) (string, error) {
	if serviceID == "" {
		return "", errors.New("service ID cannot be empty")
	}
	if targetService == "" {
		return "", errors.New("target service cannot be empty")
	}
	if ttl <= 0 {
		return "", errors.New("ttl must be greater than zero")
	}

	now := time.Now()
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   serviceID,
			Audience:  []string{BootstrapAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		Scope:       append([]string(nil), scopes...),
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"bootstrap", "offline"},
		SessionID:   fmt.Sprintf("bootstrap-%s-%d", serviceID, now.UnixNano()),
		SessionExp:  now.Add(ttl).Unix(),
		AuthEvents:  []string{"bootstrap_mint"},
	}

	additionalClaims := map[string]interface{}{
		BootstrapTokenUseField: BootstrapTokenUseClaim,
		BootstrapTargetField:   targetService,
		BootstrapScopesField:   append([]string(nil), scopes...),
		BootstrapOneTimeField:  true,
	}

	return s.TokenManager.GenerateTokenWithClaims(claims, additionalClaims)
}

// ExchangeToken exchanges an external token for an internal token
func (s *TokenService) ExchangeToken(ctx context.Context, idtoken string) (string, error) {
	if idtoken == "" {
		return "", errors.New("empty token")
	}

	// Introspect the token with the OIDC provider
	introspection, err := s.OIDCProvider.IntrospectToken(ctx, idtoken)
	if err != nil {
		return "", fmt.Errorf("token introspection failed: %w", err)
	}

	if !introspection.Active {
		return "", errors.New("token is not active")
	}

	// Create OpenCHAMI claims
	// Create OpenCHAMI claims
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   introspection.Username,
			ExpiresAt: jwt.NewNumericDate(time.Unix(introspection.ExpiresAt, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(introspection.IssuedAt, 0)),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
	}

	// Extract additional claims from introspection
	if aud, ok := introspection.Claims["aud"].([]string); ok && len(aud) > 0 {
		claims.Audience = aud
	} else if audI, ok := introspection.Claims["aud"].([]interface{}); ok && len(audI) > 0 {
		out := make([]string, 0, len(audI))
		for _, v := range audI {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			claims.Audience = out
		}
	}
	if name, ok := introspection.Claims["name"].(string); ok {
		claims.Name = name
	}
	if email, ok := introspection.Claims["email"].(string); ok {
		claims.Email = email
	}
	if emailVerified, ok := introspection.Claims["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}

	// Extract NIST-compliant claims
	if authLevel, ok := introspection.Claims["auth_level"].(string); ok {
		claims.AuthLevel = authLevel
	} else {
		return "", fmt.Errorf("missing required claim: auth_level")
	}
	if authFactors, ok := introspection.Claims["auth_factors"].(float64); ok {
		claims.AuthFactors = int(authFactors)
	} else if _, exists := introspection.Claims["auth_factors"]; !exists {
		return "", fmt.Errorf("missing required claim: auth_factors")
	} else {
		return "", fmt.Errorf("invalid type for claim auth_factors: expected number")
	}
	// Use helper function to extract auth_methods array
	authMethods := extractStringArrayFromClaims(introspection.Claims, "auth_methods")
	if len(authMethods) == 0 {
		return "", fmt.Errorf("missing required claim: auth_methods")
	}
	claims.AuthMethods = authMethods
	if sessionID, ok := introspection.Claims["session_id"].(string); ok {
		claims.SessionID = sessionID
	} else {
		return "", fmt.Errorf("missing required claim: session_id")
	}
	if sessionExp, ok := introspection.Claims["session_exp"].(float64); ok {
		claims.SessionExp = int64(sessionExp)
	} else if _, exists := introspection.Claims["session_exp"]; !exists {
		return "", fmt.Errorf("missing required claim: session_exp")
	} else {
		return "", fmt.Errorf("invalid type for claim session_exp: expected number")
	}
	if authEvents, ok := introspection.Claims["auth_events"].([]interface{}); ok {
		claims.AuthEvents = make([]string, len(authEvents))
		for i, v := range authEvents {
			if s, ok := v.(string); ok {
				claims.AuthEvents[i] = s
			}
		}
	} else {
		return "", fmt.Errorf("missing required claim: auth_events")
	}

	// Derive TokenSmith-internal scopes from upstream groups.
	//
	// NOTE: This is separate from AuthZ RBAC for OpenCHAMI services; this is only
	// about what scopes to embed in the exchanged token.
	if groupsRaw, ok := introspection.Claims["groups"]; ok {
		scopes := make([]string, 0)
		scopesSet := make(map[string]struct{})

		// groups may arrive as []string or []interface{} depending on provider.
		switch v := groupsRaw.(type) {
		case []string:
			for _, g := range v {
				for _, s := range s.GroupScopes[g] {
					scopesSet[s] = struct{}{}
				}
			}
		case []interface{}:
			for _, gi := range v {
				g, ok := gi.(string)
				if !ok {
					continue
				}
				for _, sc := range s.GroupScopes[g] {
					scopesSet[sc] = struct{}{}
				}
			}
		}

		for sc := range scopesSet {
			scopes = append(scopes, sc)
		}
		claims.Scope = scopes
	}

	// Get the scope and target service audience from the request context (set by
	// TokenExchangeHandler). These SHOULD override derived values when present.
	if scope, ok := ctx.Value(ScopeContextKey).([]string); ok {
		claims.Scope = scope
	}
	if targetService, ok := ctx.Value(TargetServiceContextKey).(string); ok && targetService != "" {
		claims.Audience = []string{targetService}
	}

	// Generate token
	idtoken, err = s.TokenManager.GenerateToken(claims)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return idtoken, nil
}

// extractStringArrayFromClaims extracts string array from claims with given key
func extractStringArrayFromClaims(claims map[string]interface{}, key string) []string {
	array, ok := claims[key].([]interface{})
	if !ok || len(array) == 0 {
		return []string{}
	}

	strings := make([]string, 0, len(array))
	for _, item := range array {
		if str, ok := item.(string); ok {
			strings = append(strings, str)
		}
	}

	return strings
}

// GenerateServiceToken generates a service-to-service token
func (s *TokenService) GenerateServiceToken(ctx context.Context, serviceID, targetService string, scopes []string) (string, error) {
	if serviceID == "" {
		return "", errors.New("service ID cannot be empty")
	}
	if targetService == "" {
		return "", errors.New("target service cannot be empty")
	}

	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   serviceID,
			Audience:  []string{targetService},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		Scope:       scopes,
		// Add NIST-compliant claims for service tokens
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"service", "certificate"},
		SessionID:   fmt.Sprintf("service-%s-%d", serviceID, time.Now().UnixNano()),
		SessionExp:  time.Now().Add(24 * time.Hour).Unix(),
		AuthEvents:  []string{"service_auth"},
	}

	return s.TokenManager.GenerateToken(claims)
}

// ValidateToken validates a token and returns its claims
func (s *TokenService) ValidateToken(ctx context.Context, token string) (*token.TSClaims, error) {
	claims, _, err := s.TokenManager.ParseToken(token)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return claims, nil
}

// UpdateGroupScopes updates the group-to-scope mapping
func (s *TokenService) UpdateGroupScopes(groupScopes map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GroupScopes = groupScopes
}

// JWKSHandler handles JWKS requests
func (s *TokenService) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	// Get public key
	publicKeyInterface, err := s.TokenManager.GetKeyManager().GetPublicKey()
	if err != nil {
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	// Type assert to RSA public key
	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		http.Error(w, "Public key is not an RSA key", http.StatusInternalServerError)
		return
	}

	// Get kid value of public key
	kid, err := s.TokenManager.GetKeyManager().GetKid()
	if err != nil {
		http.Error(w, "kid is not set", http.StatusInternalServerError)
		return
	}

	// Create JWKS manually
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

	// Marshal and return JWKS
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
		return
	}
}

// TokenExchangeHandler handles token exchange requests
func (s *TokenService) TokenExchangeHandler(w http.ResponseWriter, r *http.Request) {

	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	// Check if it's a Bearer token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	// Get the scope and audience from request payload
	var payload struct {
		Scope         []string `json:"scope"`
		TargetService string   `json:"target_service"`
	}
	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctx := context.WithValue(r.Context(), ScopeContextKey, payload.Scope)
	ctx = context.WithValue(ctx, TargetServiceContextKey, payload.TargetService)

	// Exchange token
	token, err := s.ExchangeToken(ctx, parts[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Return token
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token": token,
		"token_type":   "Bearer",
	})
}

// ServiceTokenHandler handles requests for service-to-service tokens
func (s *TokenService) ServiceTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse canonical request body.
	var req ServiceTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	serviceID, targetService, effectiveScopes, err := s.authenticateBootstrapRequest(req)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Validate target service and scopes
	if err := s.validateServiceRequest(serviceID, targetService, effectiveScopes); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Generate service token
	tokenValue, err := s.GenerateServiceToken(r.Context(), serviceID, targetService, effectiveScopes)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	claims, _, err := s.TokenManager.ParseToken(tokenValue)
	if err != nil {
		http.Error(w, "Failed to validate generated token", http.StatusInternalServerError)
		return
	}

	// Return token
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ServiceTokenResponse{
		Token:     tokenValue,
		ExpiresAt: claims.ExpiresAt.Time,
	})
}

func (s *TokenService) authenticateBootstrapRequest(req ServiceTokenRequest) (string, string, []string, error) {
	if strings.TrimSpace(req.BootstrapToken) == "" {
		return "", "", nil, errors.New("missing bootstrap token")
	}

	claims, _, err := s.TokenManager.ParseToken(req.BootstrapToken)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid bootstrap token: %w", err)
	}

	var rawClaims map[string]interface{}
	rawClaims, err = s.parseRawMapClaims(req.BootstrapToken)
	if err != nil {
		return "", "", nil, fmt.Errorf("invalid bootstrap token claims: %w", err)
	}

	if claims.Subject == "" {
		return "", "", nil, errors.New("bootstrap token subject is required")
	}

	tokenUse, _ := rawClaims[BootstrapTokenUseField].(string)
	if tokenUse != BootstrapTokenUseClaim {
		return "", "", nil, errors.New("invalid bootstrap token use")
	}

	allowedTarget, _ := rawClaims[BootstrapTargetField].(string)
	if strings.TrimSpace(allowedTarget) == "" {
		return "", "", nil, errors.New("bootstrap token target_service is required")
	}

	requestedTarget := strings.TrimSpace(req.TargetService)
	if requestedTarget == "" {
		requestedTarget = allowedTarget
	}
	if requestedTarget != allowedTarget {
		return "", "", nil, errors.New("requested target service does not match bootstrap token")
	}

	allowedScopes := extractStringSliceClaim(rawClaims, BootstrapScopesField)
	if len(allowedScopes) == 0 {
		allowedScopes = append([]string(nil), claims.Scope...)
	}

	effectiveScopes := append([]string(nil), req.Scopes...)
	if len(effectiveScopes) == 0 {
		effectiveScopes = append([]string(nil), allowedScopes...)
	}

	if !isSubset(effectiveScopes, allowedScopes) {
		return "", "", nil, errors.New("requested scopes exceed bootstrap token scopes")
	}

	if err := s.consumeBootstrapJTI(claims.ID); err != nil {
		return "", "", nil, err
	}

	return claims.Subject, requestedTarget, effectiveScopes, nil
}

func (s *TokenService) consumeBootstrapJTI(jti string) error {
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return errors.New("bootstrap token missing jti")
	}

	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()

	if s.usedBootJTI == nil {
		s.usedBootJTI = map[string]time.Time{}
	}

	if _, exists := s.usedBootJTI[jti]; exists {
		return errors.New("bootstrap token already consumed")
	}

	s.usedBootJTI[jti] = time.Now()
	if err := s.persistBootstrapJTIStoreLocked(); err != nil {
		delete(s.usedBootJTI, jti)
		return fmt.Errorf("failed to persist bootstrap token consumption: %w", err)
	}
	return nil
}

func (s *TokenService) loadBootstrapJTIStore() error {
	path := strings.TrimSpace(s.Config.BootstrapJTIStorePath)
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}

	loaded := map[string]time.Time{}
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}

	for jti, seenAt := range loaded {
		s.usedBootJTI[jti] = seenAt
	}

	return nil
}

func (s *TokenService) persistBootstrapJTIStoreLocked() error {
	path := strings.TrimSpace(s.Config.BootstrapJTIStorePath)
	if path == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s.usedBootJTI, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func extractStringSliceClaim(rawClaims map[string]interface{}, key string) []string {
	v, ok := rawClaims[key]
	if !ok {
		return nil
	}

	slice, ok := v.([]interface{})
	if !ok {
		if direct, ok := v.([]string); ok {
			return append([]string(nil), direct...)
		}
		return nil
	}

	out := make([]string, 0, len(slice))
	for _, item := range slice {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}

	return out
}

func isSubset(requested, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			allowedSet[scope] = struct{}{}
		}
	}

	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := allowedSet[scope]; !ok {
			return false
		}
	}

	return true
}

// validateServiceRequest checks if a service is allowed to request tokens for the target service
func (s *TokenService) validateServiceRequest(serviceID, targetService string, scopes []string) error {
	if serviceID == "" {
		return errors.New("service ID is required")
	}
	if targetService == "" {
		return errors.New("target service is required")
	}

	if len(scopes) == 0 {
		return nil
	}

	// Implement service-to-service authorization rules
	// This could be based on:
	// 1. Pre-configured service relationships
	// 2. Dynamic service discovery
	// 3. Service mesh configuration
	allowedTargets := s.getServiceAllowedTargets(serviceID)
	if len(allowedTargets) == 0 {
		return nil
	}
	if !allowedTargets[targetService] {
		return fmt.Errorf("service %s is not allowed to request tokens for %s", serviceID, targetService)
	}

	// Validate requested scopes
	allowedScopes := s.getServiceAllowedScopes(serviceID, targetService)
	if len(allowedScopes) == 0 {
		return nil
	}
	for _, scope := range scopes {
		if !allowedScopes[scope] {
			return fmt.Errorf("service %s is not allowed to request scope %s for %s",
				serviceID, scope, targetService)
		}
	}

	return nil
}

// getServiceAllowedTargets returns the list of services that a given service is allowed to request tokens for
func (s *TokenService) getServiceAllowedTargets(serviceID string) map[string]bool {
	// TODO: Implement service target validation
	// This should be replaced with actual service relationship logic
	// For now, return empty map and allow target validation to be driven by
	// bootstrap token claims.
	return map[string]bool{}
}

// getServiceAllowedScopes returns the list of scopes that a given service is allowed to request for a target service
func (s *TokenService) getServiceAllowedScopes(serviceID, targetService string) map[string]bool {
	// TODO: Implement scope validation
	// This should be replaced with actual scope validation logic
	// For now, return empty map and allow scope validation to be driven by
	// bootstrap token claims.
	return map[string]bool{}
}

func (s *TokenService) parseRawMapClaims(tokenString string) (map[string]interface{}, error) {
	publicKey, err := s.TokenManager.GetKeyManager().GetPublicKey()
	if err != nil {
		return nil, err
	}

	mapClaims := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, mapClaims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !parsedToken.Valid {
		return nil, errors.New("token is invalid")
	}

	return mapClaims, nil
}

// HealthHandler provides a health check endpoint
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

// Start starts the HTTP server
func (s *TokenService) Start(port int) error {
	// Setup logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	r := chi.NewRouter()

	r.Use(openchami_logger.OpenCHAMILogger(logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(60 * time.Second))

	// Health check endpoint
	r.Get("/health", s.HealthHandler)

	// Register handlers
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

	// Service token routes
	r.Route("/service", func(r chi.Router) {
		r.Post("/token", s.ServiceTokenHandler)
	})

	// Start server
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server on %s\n", addr)
	return http.ListenAndServe(addr, r)
}
