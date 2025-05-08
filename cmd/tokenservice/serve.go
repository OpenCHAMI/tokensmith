package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openchami/tokensmith/pkg/jwt"
	tokenservice "github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the token service",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		fileConfig, err := tokenservice.LoadFileConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		fmt.Printf("Provider type from flag: %q\n", providerType)

		// Create token service configuration
		serviceConfig := tokenservice.Config{
			ProviderType: tokenservice.ProviderType(providerType),
			Issuer:       issuer,
			GroupScopes:  fileConfig.GroupScopes,
			ClusterID:    clusterID,
			OpenCHAMIID:  openCHAMIID,
		}

		fmt.Printf("Provider type after conversion: %q (len=%d)\n", serviceConfig.ProviderType, len(serviceConfig.ProviderType))
		fmt.Printf("Expected constant value: %q (len=%d)\n", tokenservice.ProviderTypeAuthelia, len(tokenservice.ProviderTypeAuthelia))

		// Set provider-specific configuration
		switch serviceConfig.ProviderType {
		case tokenservice.ProviderTypeHydra:
			serviceConfig.HydraAdminURL = hydraURL
			serviceConfig.HydraClientID = os.Getenv("HYDRA_CLIENT_ID")
			serviceConfig.HydraClientSecret = os.Getenv("HYDRA_CLIENT_SECRET")
		case tokenservice.ProviderTypeAuthelia:
			serviceConfig.AutheliaURL = autheliaURL
			serviceConfig.AutheliaClientID = os.Getenv("AUTHELIA_CLIENT_ID")
			serviceConfig.AutheliaClientSecret = os.Getenv("AUTHELIA_CLIENT_SECRET")
		case tokenservice.ProviderTypeKeycloak:
			serviceConfig.KeycloakURL = keycloakURL
			serviceConfig.KeycloakRealm = keycloakRealm
			serviceConfig.KeycloakClientID = os.Getenv("KEYCLOAK_CLIENT_ID")
			serviceConfig.KeycloakClientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
		default:
			return fmt.Errorf("invalid provider type: %s", providerType)
		}

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
			if err := keyManager.GenerateKeyPair(); err != nil {
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

		// Create token service
		service, err := tokenservice.NewTokenService(nil, serviceConfig)
		if err != nil {
			return fmt.Errorf("failed to create token service: %w", err)
		}

		// Start server
		return service.Start(port)
	},
}

func init() {
	// Serve command flags
	serveCmd.Flags().StringVar(&providerType, "provider", "hydra", "OIDC provider type (hydra, keycloak, authelia)")
	serveCmd.Flags().StringVar(&issuer, "issuer", "http://tokensmith:8080", "Token issuer identifier")
	serveCmd.Flags().IntVar(&port, "port", 8080, "HTTP server port")
	serveCmd.Flags().StringVar(&clusterID, "cluster-id", "cl-F00F00F00", "Unique identifier for this cluster")
	serveCmd.Flags().StringVar(&openCHAMIID, "openchami-id", "oc-F00F00F00", "Unique identifier for this instance of OpenCHAMI")
	serveCmd.Flags().StringVar(&hydraURL, "hydra-url", "http://hydra:4445", "Hydra admin API URL")
	serveCmd.Flags().StringVar(&autheliaURL, "authelia-url", "http://authelia:9091", "Authelia admin API URL")
	serveCmd.Flags().StringVar(&keycloakURL, "keycloak-url", "http://keycloak:8080", "Keycloak admin API URL")
	serveCmd.Flags().StringVar(&keycloakRealm, "keycloak-realm", "openchami", "Keycloak realm")
	serveCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to private key file")
	serveCmd.Flags().StringVar(&keyDir, "key-dir", "", "Directory to save key files")
	rootCmd.AddCommand(serveCmd)
}
