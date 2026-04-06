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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
)

func main() {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	// Create a test token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":            "user123",
		"iss":            "example.com",
		"aud":            []string{"api.example.com"},
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"scope":          []string{"read", "write"},
		"name":           "John Doe",
		"email":          "john@example.com",
		"email_verified": true,
	})

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Example 1: Using a static key
	staticKeyMiddleware, err := authn.Middleware(authn.Options{
		Issuers:    []string{"example.com"},
		Audiences:  []string{"api.example.com"},
		StaticKeys: []crypto.PublicKey{&privateKey.PublicKey},
		Mapper:     principalMapper,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Example 2: Using JWKS URL (e.g., from Auth0)
	jwksMiddleware, err := authn.Middleware(authn.Options{
		Issuers:   []string{"example.com"},
		Audiences: []string{"api.example.com"},
		JWKSURLs:  []string{"https://your-tenant.auth0.com/.well-known/jwks.json"},
		Mapper:    principalMapper,
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

	// Protected routes with static key
	r.Group(func(r chi.Router) {
		r.Use(staticKeyMiddleware)

		r.Get("/protected-static", func(w http.ResponseWriter, r *http.Request) {
			principal, ok := authn.PrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			_, _ = fmt.Fprintf(w, "Protected route (static key) accessed by %s\n", principal.ID)
		})
	}) // Protected routes with JWKS
	r.Group(func(r chi.Router) {
		r.Use(jwksMiddleware)

		r.Get("/protected-jwks", func(w http.ResponseWriter, r *http.Request) {
			principal, ok := authn.PrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			_, _ = fmt.Fprintf(w, "Protected route (JWKS) accessed by %s\n", principal.ID)
		}) // Scope-protected routes
		r.Group(func(r chi.Router) {
			r.Use(requireRole("write"))

			r.Post("/write", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("Write access granted"))
			})
		})
	})

	// Print the test token
	fmt.Printf("Test token: %s\n", tokenString)
	fmt.Println("\nTest the endpoints:")
	fmt.Println("1. Static key protected route:")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/protected-static")
	fmt.Println("\n2. JWKS protected route:")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/protected-jwks")
	fmt.Println("\n3. Write scope protected route:")
	fmt.Println("   curl -X POST -H \"Authorization: Bearer YOUR_TOKEN\" http://localhost:8080/write")

	// Start the server
	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

func principalMapper(_ context.Context, _ *jwt.Token, claims jwt.MapClaims) (authz.Principal, error) {
	sub, _ := claims["sub"].(string)
	roles := extractScopes(claims)
	return authz.Principal{ID: sub, Roles: roles}, nil
}

func requireRole(required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := authn.PrincipalFromContext(r.Context())
			if !ok {
				http.Error(w, "Unauthorized: no principal", http.StatusUnauthorized)
				return
			}
			for _, role := range principal.Roles {
				if role == required {
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, "Insufficient scope: "+required+" required", http.StatusForbidden)
		})
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
