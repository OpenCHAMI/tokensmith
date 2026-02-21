//go:build test || !production
// +build test !production

package middleware

// TestClaimInjector provides a test-only middleware helper that injects provided
// claims into the request context, bypassing signature validation. This must only
// be used in tests and should never be enabled in production.

import (
	"context"
	"net/http"
)

// NewTestClaimInjector returns an http middleware that injects the given claims into
// the request context under the ClaimsContextKey. It is intended for use in unit
// and integration tests where generating or managing signed tokens is inconvenient.
// WARNING: This middleware must not be used in production.
func NewTestClaimInjector(claims interface{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := contextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// contextWithClaims is an internal helper that attaches the claims to the context
// using the ClaimsContextKey. Implemented here to avoid importing context directly
// in test call sites and to centralize how claims are attached.
func contextWithClaims(ctx context.Context, claims interface{}) context.Context {
	return context.WithValue(ctx, ClaimsContextKey, claims)
}
