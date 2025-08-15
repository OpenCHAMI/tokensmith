package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	tsmiddleware "github.com/openchami/tokensmith/middleware"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	hydraclient "github.com/openchami/tokensmith/pkg/oidc/hydra"
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
	tokenManager := token.NewTokenManager(keyManager, "internal-service", "test-cluster-id", "test-openchami-id")

	// Create Hydra client
	hydraClient := hydraclient.NewClient("http://hydra:4445", "test-client-id", "test-client-secret")

	// Create middleware options for internal token validation
	opts := tsmiddleware.DefaultMiddlewareOptions()
	opts.RequiredClaims = []string{"sub", "iss", "aud", "scope"}

	// Create a chi router
	r := chi.NewRouter()

	// Add some basic middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public routes
	r.Group(func(r chi.Router) {
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Welcome to the API"))
		})
	})

	// Routes protected by Hydra (external tokens)
	r.Group(func(r chi.Router) {
		r.Use(oidc.OIDCMiddleware(hydraClient))

		r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
			claims, err := tsmiddleware.GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(fmt.Sprintf("Protected route accessed by %s\n", claims.Subject)))
		})

		// Scope-protected routes
		r.Group(func(r chi.Router) {
			r.Use(tsmiddleware.RequireScope("write"))

			r.Post("/write", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("Write access granted"))
			})
		})
	})

	// Routes protected by internal tokens (service-to-service)
	r.Group(func(r chi.Router) {
		r.Use(tsmiddleware.JWTMiddleware(&privateKey.PublicKey, opts))

		r.Get("/internal", func(w http.ResponseWriter, r *http.Request) {
			claims, err := tsmiddleware.GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "Failed to get claims", http.StatusInternalServerError)
				return
			}

			w.Write([]byte(fmt.Sprintf("Internal route accessed by %s\n", claims.Subject)))
		})
	})

	// Example of creating a service-to-service token
	serviceToken, err := tokenManager.GenerateServiceToken("service-a", "service-b", []string{"read", "write"})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Example service-to-service token: %s\n", serviceToken)
	fmt.Println("\nTest the endpoints:")
	fmt.Println("1. External token protected route (requires Hydra token):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_HYDRA_TOKEN\" http://localhost:8080/protected")
	fmt.Println("\n2. Internal token protected route (requires service token):")
	fmt.Println("   curl -H \"Authorization: Bearer YOUR_SERVICE_TOKEN\" http://localhost:8080/internal")
	fmt.Println("\n3. Write scope protected route (requires write scope):")
	fmt.Println("   curl -X POST -H \"Authorization: Bearer YOUR_HYDRA_TOKEN\" http://localhost:8080/write")

	// Start the server
	log.Println("Server starting on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}
