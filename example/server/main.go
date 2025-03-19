package main

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	jwtauth "github.com/openchami/tokensmith/pkg/jwt"
	tokenservice "github.com/openchami/tokensmith/pkg/tokenservice"
)

func main() {

	// Create key manager
	keyManager := jwtauth.NewKeyManager()
	err := keyManager.GenerateKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Configure token service
	config := tokenservice.Config{
		HydraAdminURL: "http://hydra:4445", // Hydra admin API URL
		Issuer:        "https://openchami.example.com",
		Audience:      "openchami-api",
		GroupScopes: map[string][]string{
			"admin":    {"admin", "write", "read"},
			"operator": {"write", "read"},
			"viewer":   {"read"},
			"user":     {"read"},
		},
		ClusterID:   "test-cluster-id",
		OpenCHAMIID: "test-openchami-id",
	}

	// Create token service
	tokenService, err := tokenservice.NewTokenService(keyManager, config)
	if err != nil {
		log.Fatalf("Failed to create token service: %v", err)
	}

	// Create router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Routes
	r.Route("/.well-known", func(r chi.Router) {
		r.Get("/jwks.json", tokenService.JWKSHandler)
	})

	r.Route("/oauth", func(r chi.Router) {
		r.Post("/token", tokenService.TokenExchangeHandler)
	})

	// Start server
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
