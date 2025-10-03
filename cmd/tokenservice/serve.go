// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/policy"
	"github.com/openchami/tokensmith/pkg/tokenservice"
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

		// Create policy engine configuration
		policyEngineConfig, err := createPolicyEngineConfig()
		if err != nil {
			return fmt.Errorf("failed to create policy engine config: %w", err)
		}

		// Get OIDC credentials from environment variables if not provided via flags
		if oidcClientID == "" {
			oidcClientID = os.Getenv("OIDC_CLIENT_ID")
		}
		if oidcClientSecret == "" {
			oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
		}

		// Create token service configuration
		serviceConfig := tokenservice.Config{
			Issuer:           issuer,
			GroupScopes:      fileConfig.GroupScopes, // Keep for backward compatibility
			ClusterID:        clusterID,
			OpenCHAMIID:      openCHAMIID,
			NonEnforcing:     nonEnforcing,
			PolicyEngine:     policyEngineConfig,
			OIDCIssuerURL:    oidcIssuerURL,
			OIDCClientID:     oidcClientID,
			OIDCClientSecret: oidcClientSecret,
		}

		// Create key manager
		keyManager := keys.NewKeyManager()

		// Handle key loading/generation
		if keyFile != "" {
			// Load existing key
			if err := keyManager.LoadPrivateKey(keyFile); err != nil {
				return fmt.Errorf("failed to load private key: %w", err)
			}
		} else {
			// Generate new key pair
			if err := keyManager.GenerateRSAKeyPair(); err != nil {
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
	serveCmd.Flags().StringVar(&issuer, "issuer", "http://tokensmith:8080", "Token issuer identifier")
	serveCmd.Flags().IntVar(&port, "port", 8080, "HTTP server port")
	serveCmd.Flags().StringVar(&clusterID, "cluster-id", "cl-F00F00F00", "Unique identifier for this cluster")
	serveCmd.Flags().StringVar(&openCHAMIID, "openchami-id", "oc-F00F00F00", "Unique identifier for this instance of OpenCHAMI")
	serveCmd.Flags().StringVar(&oidcIssuerURL, "oidc-issuer", "http://hydra:4444", "OIDC provider issuer URL")
	serveCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID (or set OIDC_CLIENT_ID env var)")
	serveCmd.Flags().StringVar(&oidcClientSecret, "oidc-client-secret", "", "OIDC client secret (or set OIDC_CLIENT_SECRET env var)")
	serveCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to private key file")
	serveCmd.Flags().StringVar(&keyDir, "key-dir", "", "Directory to save key files")
	serveCmd.Flags().BoolVar(&nonEnforcing, "non-enforcing", false, "Skip validation checks and only log errors")

	// Policy engine flags
	serveCmd.Flags().StringVar(&policyEngineType, "policy-engine", "static", "Policy engine type (static, file-based)")
	serveCmd.Flags().StringVar(&policyConfigPath, "policy-config", "", "Path to policy configuration file (for file-based engine)")

	rootCmd.AddCommand(serveCmd)
}

// createPolicyEngineConfig creates a policy engine configuration based on command-line flags
func createPolicyEngineConfig() (*tokenservice.PolicyEngineConfig, error) {
	switch policyEngineType {
	case "static":
		return &tokenservice.PolicyEngineConfig{
			Type: tokenservice.PolicyEngineTypeStatic,
			Static: &policy.StaticEngineConfig{
				Name:          "tokensmith-static-engine",
				Version:       "1.0.0",
				Scopes:        []string{"read", "write"},
				Audiences:     []string{"smd", "bss", "cloud-init"},
				Permissions:   []string{"read:basic", "write:basic"},
				TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
				AdditionalClaims: map[string]interface{}{
					"policy_engine": "static",
					"version":       "1.0.0",
				},
			},
		}, nil
	case "file-based":
		if policyConfigPath == "" {
			return nil, fmt.Errorf("policy-config path is required for file-based policy engine")
		}
		return &tokenservice.PolicyEngineConfig{
			Type: tokenservice.PolicyEngineTypeFileBased,
			FileBased: &policy.FileBasedEngineConfig{
				Name:           "tokensmith-file-engine",
				Version:        "1.0.0",
				ConfigPath:     policyConfigPath,
				ReloadInterval: func() *time.Duration { d := 5 * time.Minute; return &d }(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported policy engine type: %s", policyEngineType)
	}
}
