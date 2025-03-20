package tokenservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtauth "github.com/openchami/tokensmith/pkg/jwt"
	"github.com/openchami/tokensmith/pkg/jwt/oidc"
	"github.com/openchami/tokensmith/pkg/jwt/oidc/authelia"
	"github.com/openchami/tokensmith/pkg/jwt/oidc/hydra"
	"github.com/openchami/tokensmith/pkg/jwt/oidc/keycloak"
)

// ProviderType represents the type of OIDC provider
type ProviderType string

const (
	ProviderTypeHydra    ProviderType = "hydra"
	ProviderTypeAuthelia ProviderType = "authelia"
	ProviderTypeKeycloak ProviderType = "keycloak"
)

// Config holds the configuration for the token service
type Config struct {
	Issuer       string
	GroupScopes  map[string][]string
	ClusterID    string
	OpenCHAMIID  string
	ProviderType ProviderType
	// Hydra-specific config
	HydraAdminURL     string
	HydraClientID     string
	HydraClientSecret string
	// Authelia-specific config
	AutheliaURL          string
	AutheliaClientID     string
	AutheliaClientSecret string
	// Keycloak-specific config
	KeycloakURL          string
	KeycloakRealm        string
	KeycloakClientID     string
	KeycloakClientSecret string
}

// TokenService handles token operations and provider interactions
type TokenService struct {
	TokenManager *jwtauth.TokenManager
	Config       Config
	Issuer       string
	GroupScopes  map[string][]string
	ClusterID    string
	OpenCHAMIID  string
	OIDCProvider oidc.Provider
	mu           sync.RWMutex
}

// NewTokenService creates a new TokenService instance
func NewTokenService(keyManager *jwtauth.KeyManager, config Config) (*TokenService, error) {
	// Initialize the token manager
	tokenManager := jwtauth.NewTokenManager(
		keyManager,
		config.Issuer,
		config.ClusterID,
		config.OpenCHAMIID,
	)

	// Initialize the appropriate OIDC provider
	var oidcProvider oidc.Provider
	switch config.ProviderType {
	case ProviderTypeHydra:
		hydraClient := hydra.NewClient(config.HydraAdminURL, config.HydraClientID, config.HydraClientSecret)
		oidcProvider = hydraClient
	case ProviderTypeAuthelia:
		autheliaClient := authelia.NewClient(config.AutheliaURL, config.AutheliaClientID, config.AutheliaClientSecret)
		oidcProvider = autheliaClient
	case ProviderTypeKeycloak:
		keycloakClient := keycloak.NewClient(
			config.KeycloakURL,
			config.KeycloakRealm,
			config.KeycloakClientID,
			config.KeycloakClientSecret,
		)
		oidcProvider = keycloakClient
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.ProviderType)
	}

	return &TokenService{
		TokenManager: tokenManager,
		Config:       config,
		Issuer:       config.Issuer,
		GroupScopes:  config.GroupScopes,
		ClusterID:    config.ClusterID,
		OpenCHAMIID:  config.OpenCHAMIID,
		OIDCProvider: oidcProvider,
	}, nil
}

// ExchangeToken exchanges an external token for an internal token
func (s *TokenService) ExchangeToken(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", errors.New("empty token")
	}

	// Introspect the token with the OIDC provider
	introspection, err := s.OIDCProvider.IntrospectToken(ctx, token)
	if err != nil {
		return "", fmt.Errorf("token introspection failed: %w", err)
	}

	if !introspection.Active {
		return "", errors.New("token is not active")
	}

	// Create OpenCHAMI claims
	claims := &jwtauth.Claims{
		Issuer:         s.Issuer,
		Subject:        introspection.Username,
		Audience:       []string{"smd", "bss", "cloud-init"},
		ExpirationTime: introspection.ExpiresAt,
		IssuedAt:       introspection.IssuedAt,
		ClusterID:      s.ClusterID,
		OpenCHAMIID:    s.OpenCHAMIID,
	}

	// Extract additional claims from introspection
	if name, ok := introspection.Claims["name"].(string); ok {
		claims.Name = name
	}
	if email, ok := introspection.Claims["email"].(string); ok {
		claims.Email = email
	}
	if emailVerified, ok := introspection.Claims["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}

	// Check for groups in claims
	groups, ok := introspection.Claims["groups"].([]interface{})
	if !ok || len(groups) == 0 {
		return "", errors.New("no groups found in token")
	}

	// Convert groups to string slice
	groupStrings := make([]string, 0, len(groups))
	for _, g := range groups {
		if gs, ok := g.(string); ok {
			groupStrings = append(groupStrings, gs)
		}
	}

	// Get scopes for groups
	scopes := make([]string, 0)
	for _, group := range groupStrings {
		if groupScopes, ok := s.GroupScopes[group]; ok {
			scopes = append(scopes, groupScopes...)
		}
	}

	// Check if we have any valid scopes
	if len(scopes) == 0 {
		return "", errors.New("no valid scopes found for groups")
	}

	// Set scopes in claims
	claims.Scope = scopes

	// Generate token
	token, err = s.TokenManager.GenerateToken(claims)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return token, nil
}

// GenerateServiceToken generates a service-to-service token
func (s *TokenService) GenerateServiceToken(ctx context.Context, serviceID, targetService string, scopes []string) (string, error) {
	claims := &jwtauth.Claims{
		Issuer:         s.Issuer,
		Subject:        serviceID,
		Audience:       []string{targetService},
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
		IssuedAt:       time.Now().Unix(),
		ClusterID:      s.ClusterID,
		OpenCHAMIID:    s.OpenCHAMIID,
		Scope:          scopes,
	}

	return s.TokenManager.GenerateToken(claims)
}

// ValidateToken validates a token and returns its claims
func (s *TokenService) ValidateToken(ctx context.Context, token string) (*jwtauth.Claims, error) {
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
	// Get public key as JWK
	publicKey, err := s.TokenManager.GetKeyManager().GetPublicJWK()
	if err != nil {
		http.Error(w, "Failed to get public key", http.StatusInternalServerError)
		return
	}

	// Create JWKS
	keySet := jwk.NewSet()
	if err := keySet.AddKey(publicKey); err != nil {
		http.Error(w, "Failed to add key to set", http.StatusInternalServerError)
		return
	}

	// Marshal and return JWKS
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(keySet); err != nil {
		http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
		return
	}
}

// TokenExchangeHandler handles token exchange requests
func (s *TokenService) TokenExchangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	// Exchange token
	token, err := s.ExchangeToken(r.Context(), parts[1])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Return token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
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

	// Verify the request is from an authorized service
	serviceID, err := s.authenticateService(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse request body
	var req struct {
		TargetService string   `json:"target_service"`
		Scopes        []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate target service and scopes
	if err := s.validateServiceRequest(serviceID, req.TargetService, req.Scopes); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Generate service token
	token, err := s.GenerateServiceToken(r.Context(), serviceID, req.TargetService, req.Scopes)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Return token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": token,
		"token_type":   "Bearer",
	})
}

// authenticateService verifies that the request is from an authorized service
func (s *TokenService) authenticateService(r *http.Request) (string, error) {
	// This could be implemented using:
	// 1. Mutual TLS (mTLS) certificates
	// 2. API keys in headers
	// 3. Service-specific authentication tokens
	// Example using API key:
	apiKey := r.Header.Get("X-Service-API-Key")
	if apiKey == "" {
		return "", errors.New("missing service API key")
	}

	// Validate API key and return service ID
	serviceID, err := s.validateServiceAPIKey(apiKey)
	if err != nil {
		return "", err
	}

	return serviceID, nil
}

// validateServiceRequest checks if a service is allowed to request tokens for the target service
func (s *TokenService) validateServiceRequest(serviceID, targetService string, scopes []string) error {
	// Implement service-to-service authorization rules
	// This could be based on:
	// 1. Pre-configured service relationships
	// 2. Dynamic service discovery
	// 3. Service mesh configuration
	allowedTargets := s.getServiceAllowedTargets(serviceID)
	if !allowedTargets[targetService] {
		return fmt.Errorf("service %s is not allowed to request tokens for %s", serviceID, targetService)
	}

	// Validate requested scopes
	allowedScopes := s.getServiceAllowedScopes(serviceID, targetService)
	for _, scope := range scopes {
		if !allowedScopes[scope] {
			return fmt.Errorf("service %s is not allowed to request scope %s for %s",
				serviceID, scope, targetService)
		}
	}

	return nil
}

// validateServiceAPIKey validates a service API key and returns the service ID
func (s *TokenService) validateServiceAPIKey(apiKey string) (string, error) {
	// TODO: Implement API key validation
	// This should be replaced with actual API key validation logic
	// For now, we'll just return a mock service ID
	return "mock-service", nil
}

// getServiceAllowedTargets returns the list of services that a given service is allowed to request tokens for
func (s *TokenService) getServiceAllowedTargets(serviceID string) map[string]bool {
	// TODO: Implement service target validation
	// This should be replaced with actual service relationship logic
	// For now, we'll just return a mock allowed target
	return map[string]bool{
		"mock-target": true,
	}
}

// getServiceAllowedScopes returns the list of scopes that a given service is allowed to request for a target service
func (s *TokenService) getServiceAllowedScopes(serviceID, targetService string) map[string]bool {
	// TODO: Implement scope validation
	// This should be replaced with actual scope validation logic
	// For now, we'll just return a mock allowed scope
	return map[string]bool{
		"mock-scope": true,
	}
}

// Start starts the HTTP server
func (s *TokenService) Start(port int) error {
	r := chi.NewRouter()

	// Register handlers
	r.Route("/.well-known", func(r chi.Router) {
		r.Get("/jwks.json", s.JWKSHandler)
	})

	r.Route("/oauth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(oidc.RequireToken)
			r.Use(oidc.RequireValidToken(s.OIDCProvider))
			r.Post("/token", s.TokenExchangeHandler)
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
