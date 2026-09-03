// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
)

// ExchangeToken exchanges an external token for an internal token.
func (s *TokenService) ExchangeToken(ctx context.Context, idtoken string) (string, error) {
	if idtoken == "" {
		return "", errors.New("empty token")
	}

	introspection, ok := ctx.Value(oidc.IntrospectionCtxKey{}).(*oidc.IntrospectionResponse)
	if !ok {
		provider := s.currentOIDCProvider()
		if provider == nil {
			return "", errors.New("OIDC provider is not configured")
		}

		var err error
		introspection, err = provider.IntrospectToken(ctx, idtoken)
		if err != nil {
			return "", fmt.Errorf("token introspection failed: %w", err)
		}
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

	if audience := normalizeAudienceClaim(introspection.Claims["aud"]); len(audience) > 0 {
		claims.Audience = audience
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

	if err := normalizeExchangeClaims(introspection.Claims, claims, s.Config.OIDCClaimPolicy); err != nil {
		return "", err
	}
	capExchangeSession(claims, s.Config.MaxExchangeSessionLifetime)

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
		sort.Strings(scopes)
		claims.Scope = scopes
	}

	// Authentication is not authorization. A caller the provider happily
	// authenticates may still map to no scope in this cluster, and a signed but
	// scopeless token defers that decision to every resource server -- one of
	// them treating a missing scope claim as unrestricted turns it into an
	// access-control failure.
	//
	// Off by default: service accounts legitimately carry no groups, and
	// refusing them would break client-credentials flows. Deployments where
	// every caller is expected to map to a group can opt in.
	if s.Config.RequireAuthorizedGroup && len(claims.Scope) == 0 {
		return "", ErrExchangeNoAuthorizedGroups
	}

	if scope, ok := ctx.Value(ScopeContextKey).([]string); ok && len(scope) > 0 {
		filtered, err := constrainRequestedScopes(claims.Scope, scope)
		if err != nil {
			return "", err
		}
		claims.Scope = filtered
	}
	if targetService, ok := ctx.Value(TargetServiceContextKey).(string); ok && targetService != "" {
		claims.Audience = []string{targetService}
	}

	tokenValue, err := s.TokenManager.GenerateToken(claims)
	if err != nil {
		if errors.Is(err, token.ErrInvalidClaims) {
			return "", fmt.Errorf("%w: %w", ErrExchangeGeneratedClaimValidation, err)
		}
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	return tokenValue, nil
}

func capExchangeSession(claims *token.TSClaims, maxLifetime time.Duration) {
	if claims == nil || claims.IssuedAt == nil {
		return
	}
	if maxLifetime <= 0 {
		maxLifetime = DefaultMaxExchangeSessionLifetime
	}

	deadline := claims.IssuedAt.Add(maxLifetime)
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(deadline) {
		deadline = claims.ExpiresAt.Time
	}
	if claims.SessionExp > 0 {
		sessionDeadline := time.Unix(claims.SessionExp, 0)
		if sessionDeadline.Before(deadline) {
			deadline = sessionDeadline
		}
	}

	claims.ExpiresAt = jwt.NewNumericDate(deadline)
	claims.SessionExp = deadline.Unix()
}

func normalizeAudienceClaim(value interface{}) []string {
	switch audience := value.(type) {
	case string:
		if audience == "" {
			return nil
		}
		return []string{audience}
	case []string:
		return compactStrings(audience)
	case []interface{}:
		out := make([]string, 0, len(audience))
		for _, item := range audience {
			if value, ok := item.(string); ok && value != "" {
				out = append(out, value)
			}
		}
		return out
	default:
		return nil
	}
}

func constrainRequestedScopes(allowed []string, requested []string) ([]string, error) {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return nil, invalidExchangeClaim("scope")
		}
		out = append(out, scope)
	}
	return out, nil
}
