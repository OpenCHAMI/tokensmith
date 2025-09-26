package oidc

import (
	"context"
	"net/http"
	"strings"
)

// TokenCtxKey is the context key for the OIDC token
type TokenCtxKey struct{}

// IntrospectionCtxKey is the context key for the OIDC introspection result
type IntrospectionCtxKey struct{}

// RequireToken is middleware that validates the presence and format of an OIDC token
func RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Add token to request context for downstream handlers
		ctx := context.WithValue(r.Context(), TokenCtxKey{}, parts[1])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireValidToken is middleware that validates the token with the OIDC provider
func RequireValidToken(provider Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from context (set by RequireToken middleware)
			token, ok := r.Context().Value(TokenCtxKey{}).(string)
			if !ok {
				http.Error(w, "Invalid token in context", http.StatusUnauthorized)
				return
			}

			// Use the provider's introspection method (handles both local and remote)
			introspection, err := provider.IntrospectToken(r.Context(), token)
			if err != nil {
				http.Error(w, "Token introspection failed", http.StatusUnauthorized)
				return
			}

			if !introspection.Active {
				http.Error(w, "Token is not active", http.StatusUnauthorized)
				return
			}

			// Add introspection result to context for downstream handlers
			ctx := context.WithValue(r.Context(), IntrospectionCtxKey{}, introspection)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
