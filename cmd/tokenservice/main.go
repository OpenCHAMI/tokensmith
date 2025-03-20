package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/openchami/tokensmith/pkg/jwt"
	tokenservice "github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

var (
	// Flags
	hydraURL      string
	autheliaURL   string
	keycloakURL   string
	keycloakRealm string
	oidcProvider  string
	issuer        string
	port          int
	keyFile       string
	keyDir        string
	groupScopes   map[string][]string
	clusterID     string
	openchamiID   string

	rootCmd = &cobra.Command{
		Use:   "tokenservice",
		Short: "OpenCHAMI Token Service",
		Long: `The OpenCHAMI Token Service provides JWT token management and integration with Hydra.
It allows users authenticated through Hydra to obtain OpenCHAMI-specific tokens with appropriate scopes based on their group membership.`,
		RunE: run,
	}
)

func init() {
	// Initialize flags
	rootCmd.Flags().StringVar(&oidcProvider, "oidc-provider", "hydra", "OIDC provider (hydra, authelia, keycloak)")
	rootCmd.Flags().StringVar(&hydraURL, "hydra-url", "http://hydra:4445", "Hydra admin API URL")
	rootCmd.Flags().StringVar(&autheliaURL, "authelia-url", "http://authelia:9091", "Authelia admin API URL")
	rootCmd.Flags().StringVar(&keycloakURL, "keycloak-url", "http://keycloak:8080", "Keycloak admin API URL")
	rootCmd.Flags().StringVar(&keycloakRealm, "keycloak-realm", "openchami", "Keycloak realm")
	rootCmd.Flags().StringVar(&issuer, "issuer", "https://openchami.example.com", "Token issuer")
	rootCmd.Flags().IntVar(&port, "port", 8080, "Server port")
	rootCmd.Flags().StringVar(&keyFile, "key-file", "", "RSA private key file (if not provided, generates a new key)")
	rootCmd.Flags().StringVar(&keyDir, "key-dir", "keys", "Directory for storing key files")
	rootCmd.Flags().StringVar(&clusterID, "cluster-id", "test-cluster-id", "Cluster ID")
	rootCmd.Flags().StringVar(&openchamiID, "openchami-id", "test-openchami-id", "OpenCHAMI ID")
	// Initialize group scopes map
	groupScopes = map[string][]string{
		"admin":    {"admin", "write", "read"},
		"operator": {"write", "read"},
		"viewer":   {"read"},
		"user":     {"read"},
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Create key manager
	keyManager := jwt.NewKeyManager()

	// Handle key loading/generation
	if keyFile != "" {
		// Load existing key
		if err := keyManager.LoadPrivateKey(keyFile); err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}
	} else {
		// Generate new key pair
		if err := keyManager.GenerateKeyPair(2048); err != nil {
			return fmt.Errorf("failed to generate key pair: %w", err)
		}

		// Save keys to disk
		privateKeyPath := filepath.Join(keyDir, "private.pem")
		publicKeyPath := filepath.Join(keyDir, "public.pem")

		if err := keyManager.SavePrivateKey(privateKeyPath); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}

		if err := keyManager.SavePublicKey(publicKeyPath); err != nil {
			return fmt.Errorf("failed to save public key: %w", err)
		}

		fmt.Printf("Generated new key pair:\n")
		fmt.Printf("  Private key: %s\n", privateKeyPath)
		fmt.Printf("  Public key:  %s\n", publicKeyPath)
	}

	// Configure token service
	config := tokenservice.Config{
		Issuer:      issuer,
		GroupScopes: groupScopes,
		ClusterID:   clusterID,
		OpenCHAMIID: openchamiID,
	}

	// Read oidc provider type from flag and read environment variables for Client Key and Secret
	oidcProviderType := tokenservice.ProviderType(oidcProvider)
	switch oidcProviderType {
	case tokenservice.ProviderTypeHydra:
		config.HydraAdminURL = hydraURL
		config.HydraClientID = os.Getenv("HYDRA_CLIENT_ID")
		config.HydraClientSecret = os.Getenv("HYDRA_CLIENT_SECRET")
	case tokenservice.ProviderTypeAuthelia:
		config.AutheliaURL = autheliaURL
	case tokenservice.ProviderTypeKeycloak:
		config.KeycloakURL = keycloakURL
		config.KeycloakRealm = keycloakRealm
		config.KeycloakClientID = os.Getenv("KEYCLOAK_CLIENT_ID")
		config.KeycloakClientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
	default:
		return fmt.Errorf("invalid OIDC provider type: %s", oidcProvider)
	}

	// Create token service
	tokenService, err := tokenservice.NewTokenService(keyManager, config)
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
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

	// Service token routes
	r.Route("/service", func(r chi.Router) {
		r.Post("/token", tokenService.ServiceTokenHandler)
	})

	// Start server
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Starting server on %s\n", addr)
	return http.ListenAndServe(addr, r)
}
