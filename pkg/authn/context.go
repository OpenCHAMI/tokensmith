// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authn

import (
	"context"
	"slices"

	"github.com/openchami/tokensmith/pkg/authz"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

type principalContextKey struct{}

type claimsContextKey struct{}

type humanClaimsContextKey struct{}

// HumanSessionClaimsFromContext returns a defensive copy of verified human claims.
func HumanSessionClaimsFromContext(ctx context.Context) (*tstoken.HumanSessionClaims, bool) {
	c, ok := ctx.Value(humanClaimsContextKey{}).(tstoken.HumanSessionClaims)
	if !ok {
		return nil, false
	}
	c.Audience = slices.Clone(c.Audience)
	return &c, true
}

// ContextWithPrincipal returns a derived context containing the principal.
func ContextWithPrincipal(ctx context.Context, p authz.Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// PrincipalFromContext returns the principal stored in ctx, if any.
func PrincipalFromContext(ctx context.Context) (authz.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(authz.Principal)
	return p, ok
}

// ContextWithVerifiedClaims stores verified JWT claims in the context.
//
// Claims are stored only for cases where services need additional fields beyond
// what is captured in authz.Principal.
func ContextWithVerifiedClaims(ctx context.Context, c map[string]any) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, c)
}

// VerifiedClaimsFromContext returns verified JWT claims, if present.
func VerifiedClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(map[string]any)
	return c, ok
}
