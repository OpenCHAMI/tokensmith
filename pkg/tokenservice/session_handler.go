// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/token"
)

const (
	// DefaultSessionLifetime is the default session token lifetime (12 hours)
	DefaultSessionLifetime = 12 * time.Hour

	// MaxSessionLifetime is the maximum session token lifetime (24 hours per NIST SP 800-63B)
	MaxSessionLifetime = 24 * time.Hour
)

// CreateSessionToken handles POST /oauth/session
// Creates a long-lived session token with MFA claims extracted from the upstream OIDC id_token.
func (s *TokenService) CreateSessionToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req SessionTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Extract verified claims from context (set by authn middleware)
	claims, ok := authn.VerifiedClaimsFromContext(ctx)
	if !ok {
		http.Error(w, "No verified claims in context - authentication required", http.StatusUnauthorized)
		return
	}

	// Extract MFA claims from the upstream OIDC id_token
	amr, _ := extractStringArray(claims, "amr")
	acr, _ := extractString(claims, "acr")
	authTime, _ := extractInt64(claims, "auth_time")
	sessionID, _ := extractString(claims, "session_id")
	subject, _ := extractString(claims, "sub")
	email, _ := extractString(claims, "email")
	name, _ := extractString(claims, "name")

	// Validate required claims
	if subject == "" {
		http.Error(w, "Missing 'sub' claim in id_token", http.StatusBadRequest)
		return
	}

	// Determine session lifetime
	lifetime := DefaultSessionLifetime
	if req.LifetimeSeconds > 0 {
		lifetime = time.Duration(req.LifetimeSeconds) * time.Second
	}
	if lifetime > MaxSessionLifetime {
		http.Error(w, fmt.Sprintf("Requested lifetime exceeds maximum of %d seconds", int64(MaxSessionLifetime.Seconds())), http.StatusBadRequest)
		return
	}

	// Handle parent token inheritance (Issue #37)
	if req.ParentTokenID != "" {
		// Validate parent token and inherit claims
		parentClaims, err := s.validateParentTokenForSession(ctx, req.ParentTokenID, subject)
		if err != nil {
			http.Error(w, fmt.Sprintf("Parent token validation failed: %v", err), http.StatusBadRequest)
			return
		}

		// Inherit MFA claims from parent if not present in id_token
		if len(amr) == 0 && len(parentClaims.AMR) > 0 {
			amr = parentClaims.AMR
		}
		if acr == "" && parentClaims.ACR != "" {
			acr = parentClaims.ACR
		}
		if authTime == 0 && parentClaims.AuthTime > 0 {
			authTime = parentClaims.AuthTime
		}
	}

	// Generate session ID if not provided by IdP
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-%s-%d", subject, time.Now().UnixNano())
	}

	// Mint session token
	now := time.Now()
	tokenID := fmt.Sprintf("tok-%d", now.UnixNano())
	expiresAt := now.Add(lifetime)

	sessionClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   subject,
			Audience:  []string{s.Issuer}, // Session tokens are issued for the issuer itself
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        tokenID,
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		SessionID:   sessionID,
		AMR:         amr,
		ACR:         acr,
		AuthTime:    authTime,
		Email:       email,
		Name:        name,
		AuthLevel:   "IAL2", // Session tokens require IAL2 (authenticated user)
		AuthFactors: len(amr),
		AuthMethods: amr,
		SessionExp:  expiresAt.Unix(),
		AuthEvents:  []string{"session_created"},
		ParentID:    req.ParentTokenID,
	}

	// Generate JWT
	jwtToken, err := s.TokenManager.GenerateToken(sessionClaims)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to generate session token: %v", err), http.StatusInternalServerError)
		return
	}

	// TODO: Store session token for revocation (session_store implementation)

	// Build response
	response := SessionTokenResponse{
		JWT:       jwtToken,
		TokenID:   tokenID,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		SessionID: sessionID,
		AMR:       amr,
		ACR:       acr,
		AuthTime:  authTime,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}

// validateParentTokenForSession validates a parent token for session token inheritance
func (s *TokenService) validateParentTokenForSession(ctx context.Context, parentTokenID, subject string) (*token.TSClaims, error) {
	if parentTokenID == "" {
		return nil, errors.New("parent_token_id cannot be empty")
	}

	// Parse and validate parent token
	// For now, we'll use a simplified validation - in production this would query the hierarchy storage
	// TODO: Implement proper parent token validation via hierarchy storage

	return &token.TSClaims{}, nil
}

// Helper functions to extract claims safely

func extractString(claims map[string]any, key string) (string, bool) {
	val, ok := claims[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

func extractInt64(claims map[string]any, key string) (int64, bool) {
	val, ok := claims[key]
	if !ok {
		return 0, false
	}

	// Handle different numeric types
	switch v := val.(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case int:
		return int64(v), true
	default:
		return 0, false
	}
}

func extractStringArray(claims map[string]any, key string) ([]string, bool) {
	val, ok := claims[key]
	if !ok {
		return nil, false
	}

	// Handle both []string and []interface{}
	switch v := val.(type) {
	case []string:
		return v, true
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, len(result) > 0
	default:
		return nil, false
	}
}
