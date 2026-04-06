// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
)

func main() {
	// Generate a test RSA key pair for internal tokens
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create key manager for internal tokens
	keyManager := keys.NewKeyManager()
	if err := keyManager.SetKeyPair(privateKey, &privateKey.PublicKey); err != nil {
		log.Fatal(err)
	}
	tokenManager := token.NewTokenManager(keyManager, "internal-service", "test-cluster-id", "test-openchami-id", false)

	// Create simplified OIDC provider (works with any OIDC-compliant provider including Hydra)
	oidcProvider := oidc.NewSimpleProvider("http://hydra:4444", "test-client-id", "test-client-secret")

	internalAuthn, err := authn.Middleware(authn.Options{
		Issuers:    []string{"internal-service"},
		Audiences:  []string{"service-b"},
		StaticKeys: []crypto.PublicKey{&privateKey.PublicKey},
		Mapper: func(_ context.Context, _ *jwt.Token, claims jwt.MapClaims) (authz.Principal, error) {
			sub, _ := claims["sub"].(string)
			return authz.Principal{ID: sub, Roles: extractScopes(claims)}, nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create a chi router
	r := chi.NewRouter()

	// Add some basic middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("Welcome to the API"))
		})
	})

	// Routes protected by OIDC provider (external tokens)
	r.Group(func(r chi.Router) {
		r.Use(oidc.RequireToken)
		r.Use(oidc.RequireValidToken(oidcProvider))

		r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
			// Get introspection result from OIDC context
			introspection, ok := r.Context().Value(oidc.IntrospectionCtxKey{}).(*oidc.IntrospectionResponse)
			if !ok {
				http.Error(w, "Failed to get introspection result", http.StatusInternalServerError)
				return
			}

			_, _ = fmt.Fprintf(w, "Protected route accessed by %s\n", introspection.Username)
		}) // Scope-protected routes
		r.Group(func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Get introspection result from OIDC context
					introspection, ok := r.Context().Value(oidc.IntrospectionCtxKey{}).(*oidc.IntrospectionResponse)
					if !ok {
						http.Error(w, "Failed to get introspection result", http.StatusInternalServerError)
						return
					}

					// Check if user has write scope
					hasWriteScope := false
					if scopes, ok := introspection.Claims["scope"].(string); ok {
						// Simple scope check - in production you'd want more sophisticated scope parsing
						if scopes == "write" || scopes == "read write" || scopes == "write read" {
							hasWriteScope = true
						}
					}

					if !hasWriteScope {
						http.Error(w, "Insufficient scope: write required", http.StatusForbidden)
						return
					}

					next.ServeHTTP(w, r)
				})
			})

			r.Post("/write", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("Write access granted"))
			})
		})
	})

	// Routes protected by internal tokens (service-to-service)
	r.Group(func(r chi.Router) {
		r.Use(internalAuthn)

		r.Get("/internal", func(w http.ResponseWriter, r *http.Request) {
			principal, ok := authn.PrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			_, _ = fmt.Fprintf(w, "Internal route accessed by %s\n", principal.ID)
		})
	}) // Example of creating a service-to-service token
	serviceToken, err := tokenManager.GenerateServiceToken("service-a", "service-b", []string{"read", "write"})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Example service-to-service token: %s\n", serviceToken)
	fmt.Println("\nTest the endpoints:")
	fmt.Println("1. External token protected route (requires OIDC token from Hydra):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_OIDC_TOKEN\" http://localhost:8080/protected")
	fmt.Println("\n2. Internal token protected route (requires service token):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_SERVICE_TOKEN\" http://localhost:8080/internal")
	fmt.Println("\n3. Write scope protected route (requires write scope in OIDC token):")
	fmt.Println("   curl -X POST -H \"Authorization: Bearer YOUR_OIDC_TOKEN\" http://localhost:8080/write")

	// Start the server
	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

func extractScopes(claims jwt.MapClaims) []string {
	raw, ok := claims["scope"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return strings.Fields(v)
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, it := range v {
			if s, ok := it.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
