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
		for index, value := range authEvents {
			if authEvent, ok := value.(string); ok {
				claims.AuthEvents[index] = authEvent
			}
		}
	} else {
		return "", fmt.Errorf("missing required claim: auth_events")
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
