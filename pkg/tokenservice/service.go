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

	"github.com/lestrrat-go/jwx/v2/jwk"

	jwtauth "github.com/openchami/tokensmith/pkg/jwt"
)

// TokenService handles token exchange and management
type TokenService struct {
	TokenManager *jwtauth.TokenManager
	Config       Config
	HydraClient  jwtauth.HydraClient
	Issuer       string
	Audience     string
	// Group to scope mapping
	GroupScopes map[string][]string
	ClusterID   string
	OpenCHAMIID string
	mu          sync.RWMutex
}

// Config holds the configuration for TokenService
type Config struct {
	// HydraAdminURL is the URL of the Hydra admin API
	HydraAdminURL string
	// Issuer is the issuer identifier for OpenCHAMI tokens
	Issuer string
	// Audience is the audience for OpenCHAMI tokens
	Audience string
	// GroupScopes maps Hydra group claims to OpenCHAMI scopes
	GroupScopes map[string][]string
	// ClusterID is the ID of the cluster
	ClusterID string
	// OpenCHAMIID is the ID of the OpenCHAMI instance
	OpenCHAMIID string
}

// NewTokenService creates a new TokenService instance
func NewTokenService(keyManager *jwtauth.KeyManager, config Config) *TokenService {
	return &TokenService{
		TokenManager: jwtauth.NewTokenManager(keyManager, config.Issuer, config.ClusterID, config.OpenCHAMIID),
		Config:       config,
		HydraClient:  jwtauth.NewHydraClient(config.HydraAdminURL),
		Issuer:       config.Issuer,
		Audience:     config.Audience,
		GroupScopes:  config.GroupScopes,
	}
}

// ExchangeToken exchanges a Hydra token for an OpenCHAMI token
func (s *TokenService) ExchangeToken(ctx context.Context, hydraToken string) (string, error) {
	// Introspect token with Hydra
	hydraResp, err := s.HydraClient.IntrospectToken(ctx, hydraToken)
	if err != nil {
		return "", fmt.Errorf("token introspection failed: %w", err)
	}

	if !hydraResp.Active {
		return "", fmt.Errorf("token is not active")
	}

	// Extract groups from Hydra token
	groups, ok := hydraResp.Ext["groups"].([]interface{})
	if !ok {
		return "", fmt.Errorf("no groups found in token")
	}

	// Collect scopes based on groups
	var scopes []string
	s.mu.RLock()
	for _, group := range groups {
		if groupStr, ok := group.(string); ok {
			if groupScopes, exists := s.GroupScopes[groupStr]; exists {
				scopes = append(scopes, groupScopes...)
			}
		}
	}
	s.mu.RUnlock()

	// Create OpenCHAMI claims
	now := time.Now()
	claims := &jwtauth.Claims{
		Issuer:         s.Issuer,
		Subject:        hydraResp.Sub,
		Audience:       []string{s.Audience},
		ExpirationTime: now.Add(1 * time.Hour).Unix(),
		NotBefore:      now.Unix(),
		IssuedAt:       now.Unix(),
		Scope:          scopes,
	}

	// Copy user information from Hydra token
	if name, ok := hydraResp.Ext["name"].(string); ok {
		claims.Name = name
	}
	if email, ok := hydraResp.Ext["email"].(string); ok {
		claims.Email = email
	}
	if emailVerified, ok := hydraResp.Ext["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}

	// Generate OpenCHAMI token
	return s.TokenManager.GenerateToken(claims)
}

// UpdateGroupScopes updates the group to scope mapping
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

// GenerateServiceToken generates a token for service-to-service communication
func (s *TokenService) GenerateServiceToken(ctx context.Context, serviceID, targetService string, scopes []string) (string, error) {
	return s.TokenManager.GenerateServiceToken(serviceID, targetService, scopes)
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
