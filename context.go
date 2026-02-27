// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokensmith

import (
	"context"

	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/token"
)

// principalCtxKey is TokenSmith's canonical context key for *authz.Principal.
//
// This key is intentionally defined at the module root package so both chi and
// net/http middleware stacks can share a stable principal location without
// importing router-specific packages.
//
// See docs/migration.md.
type principalCtxKey struct{}

// claimsCtxKey is TokenSmith's legacy context key for *token.TSClaims.
//
// NOTE: The historical JWT middleware lives in a separate Go module
// (./middleware) and uses its own ContextKey type with the string value
// "jwt_claims". We mirror that string value here so the root module can read
// legacy claims without importing the nested module.
type claimsCtxKey string

const legacyClaimsContextKey claimsCtxKey = "jwt_claims"

// SetPrincipal stores p into ctx using TokenSmith's canonical principal context key.
func SetPrincipal(ctx context.Context, p *authz.Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// PrincipalFromContext returns the authorization principal stored in ctx.
//
// Compatibility strategy (read-new then read-old):
//  1. If a *authz.Principal was stored using tokensmith.SetPrincipal, return it.
//  2. Else, if legacy JWT claims exist in ctx under the legacy key, derive a
//     minimal principal from those claims.
//
// Legacy-derived principal mapping:
//   - ID: claims.Subject
//   - Roles: claims.Scope
func PrincipalFromContext(ctx context.Context) (*authz.Principal, bool) {
	if p, ok := ctx.Value(principalCtxKey{}).(*authz.Principal); ok && p != nil {
		return p, true
	}

	claims, err := ClaimsFromContext(ctx)
	if err != nil || claims == nil || claims.Subject == "" {
		return nil, false
	}

	return &authz.Principal{ID: claims.Subject, Roles: append([]string(nil), claims.Scope...)}, true
}

// ClaimsFromContext returns legacy TokenSmith JWT claims stored in request context.
//
// Deprecated: new services should prefer mapping verified claims into an
// authz.Principal and storing it using tokensmith.SetPrincipal, then use
// tokensmith.PrincipalFromContext.
func ClaimsFromContext(ctx context.Context) (*token.TSClaims, error) {
	claims, ok := ctx.Value(legacyClaimsContextKey).(*token.TSClaims)
	if !ok || claims == nil {
		return nil, context.Canceled // sentinel; legacy claims not found
	}
	return claims, nil
}
