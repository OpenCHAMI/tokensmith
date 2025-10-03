// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"time"

	tsmiddleware "github.com/openchami/tokensmith/middleware"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
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

	// Create middleware options
	opts := tsmiddleware.DefaultMiddlewareOptions()
	opts.RequiredClaims = []string{"sub", "iss", "aud", "scope"}

	// Example 1: Using static key
	staticKeyMiddleware := tsmiddleware.JWTMiddleware(&privateKey.PublicKey, opts)

	// Example 2: Using JWKS URL (e.g., from Auth0)
	optsWithJWKS := *opts
	optsWithJWKS.JWKSURL = "https://your-tenant.auth0.com/.well-known/jwks.json"
	optsWithJWKS.JWKSRefreshInterval = 15 * time.Minute
	jwksMiddleware := tsmiddleware.JWTMiddleware(nil, &optsWithJWKS)

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
			claims, err := tsmiddleware.GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			_, _ = fmt.Fprintf(w, "Protected route (static key) accessed by %s\n", claims.Subject)
		})
	}) // Protected routes with JWKS
	r.Group(func(r chi.Router) {
		r.Use(jwksMiddleware)

		r.Get("/protected-jwks", func(w http.ResponseWriter, r *http.Request) {
			claims, err := tsmiddleware.GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			_, _ = fmt.Fprintf(w, "Protected route (JWKS) accessed by %s\n", claims.Subject)
		}) // Scope-protected routes
		r.Group(func(r chi.Router) {
			r.Use(tsmiddleware.RequireScope("write"))

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
