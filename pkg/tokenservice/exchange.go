// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/token"
)

// ExchangeToken exchanges an external token for an internal token.
func (s *TokenService) ExchangeToken(ctx context.Context, idtoken string) (string, error) {
	if idtoken == "" {
		return "", errors.New("empty token")
	}

	provider := s.currentOIDCProvider()
	if provider == nil {
		return "", errors.New("OIDC provider is not configured")
	}

	introspection, err := provider.IntrospectToken(ctx, idtoken)
	if err != nil {
		return "", fmt.Errorf("token introspection failed: %w", err)
	}

	if !introspection.Active {
		return "", errors.New("token is not active")
	}

	issuedAt := time.Unix(introspection.IssuedAt, 0)
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   introspection.Username,
			ExpiresAt: jwt.NewNumericDate(time.Unix(introspection.ExpiresAt, 0)),
			NotBefore: jwt.NewNumericDate(issuedAt),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
	}

	if aud, ok := introspection.Claims["aud"].([]string); ok && len(aud) > 0 {
		claims.Audience = aud
	} else if audI, ok := introspection.Claims["aud"].([]interface{}); ok && len(audI) > 0 {
		out := make([]string, 0, len(audI))
		for _, value := range audI {
			if audience, ok := value.(string); ok {
				out = append(out, audience)
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

	// Extract standard OIDC MFA claims (amr, acr, auth_time)
	// Per OIDC Core 1.0 Section 2: Authentication Methods Reference (amr)
	amr := extractStringArrayFromClaims(introspection.Claims, "amr")
	if len(amr) > 0 {
		claims.AMR = amr
	}

	// Authentication Context Class Reference (acr)
	if acr, ok := introspection.Claims["acr"].(string); ok && acr != "" {
		claims.ACR = acr
	}

	// Authentication time (auth_time) - when user actually authenticated
	if authTime, ok := introspection.Claims["auth_time"].(float64); ok {
		claims.AuthTime = int64(authTime)
	}

	// Extract custom NIST claims (optional for backward compatibility)
	// If present, use them; otherwise derive from standard OIDC claims
	if authLevel, ok := introspection.Claims["auth_level"].(string); ok {
		claims.AuthLevel = authLevel
	}

	// Derive AuthFactors from AMR if not explicitly provided
	if authFactors, ok := introspection.Claims["auth_factors"].(float64); ok {
		claims.AuthFactors = int(authFactors)
	} else if len(amr) > 0 {
		// Derive auth factors by counting distinct factor categories from AMR
		// Per NIST SP 800-63B: knowledge (pwd), possession (otp, sms), inherence (bio, fido2)
		claims.AuthFactors = deriveAuthFactorsFromAMR(amr)
	}

	// Extract auth_methods from custom claim or map from AMR for backward compatibility
	authMethods := extractStringArrayFromClaims(introspection.Claims, "auth_methods")
	if len(authMethods) > 0 {
		claims.AuthMethods = authMethods
	} else if len(amr) > 0 {
		// Map AMR to AuthMethods for backward compatibility
		claims.AuthMethods = amr
	}

	// Extract custom session claims (optional)
	if sessionID, ok := introspection.Claims["session_id"].(string); ok {
		claims.SessionID = sessionID
	}
	if sessionExp, ok := introspection.Claims["session_exp"].(float64); ok {
		claims.SessionExp = int64(sessionExp)
	}

	// Extract auth_events (optional)
	if authEvents, ok := introspection.Claims["auth_events"].([]interface{}); ok {
		claims.AuthEvents = make([]string, len(authEvents))
		for index, value := range authEvents {
			if authEvent, ok := value.(string); ok {
				claims.AuthEvents[index] = authEvent
			}
		}
	}

	if groupsRaw, ok := introspection.Claims["groups"]; ok {
		scopes := make([]string, 0)
		scopesSet := make(map[string]struct{})

		switch groups := groupsRaw.(type) {
		case []string:
			for _, group := range groups {
				for _, scope := range s.GroupScopes[group] {
					scopesSet[scope] = struct{}{}
				}
			}
		case []interface{}:
			for _, groupValue := range groups {
				group, ok := groupValue.(string)
				if !ok {
					continue
				}
				for _, scope := range s.GroupScopes[group] {
					scopesSet[scope] = struct{}{}
				}
			}
		}

		for scope := range scopesSet {
			scopes = append(scopes, scope)
		}
		claims.Scope = scopes
	}

	if scope, ok := ctx.Value(ScopeContextKey).([]string); ok {
		claims.Scope = scope
	}
	if targetService, ok := ctx.Value(TargetServiceContextKey).(string); ok && targetService != "" {
		claims.Audience = []string{targetService}
	}

	idtoken, err = s.TokenManager.GenerateToken(claims)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return idtoken, nil
}

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

func deriveAuthFactorsFromAMR(amr []string) int {
	factorCategories := make(map[string]bool)

	for _, method := range amr {
		switch method {
		case "pwd", "pin", "kba":
			factorCategories["knowledge"] = true
		case "otp", "sms", "hwk", "swk":
			factorCategories["possession"] = true
		case "bio", "fido2", "fido", "face", "fpt", "iris", "retina", "vbm":
			factorCategories["inherence"] = true
		default:
			factorCategories["other"] = true
		}
	}

	return len(factorCategories)
}
