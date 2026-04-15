// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/openchami/tokensmith/pkg/keys"
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

		// Get OIDC credentials from environment variables if not provided via flags
		if oidcClientID == "" {
			oidcClientID = os.Getenv("OIDC_CLIENT_ID")
		}
		if oidcClientSecret == "" {
			oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
		}
		if rfc8693BootstrapStorePath == "" {
			rfc8693BootstrapStorePath = os.Getenv("TOKENSMITH_RFC8693_BOOTSTRAP_STORE")
			if rfc8693BootstrapStorePath == "" {
				rfc8693BootstrapStorePath = "./data/bootstrap-tokens"
			}
		}
		if rfc8693RefreshStorePath == "" {
			rfc8693RefreshStorePath = os.Getenv("TOKENSMITH_RFC8693_REFRESH_STORE")
			if rfc8693RefreshStorePath == "" {
				rfc8693RefreshStorePath = "./data/refresh-tokens"
			}
		}

		// Create token service configuration
		serviceConfig := tokenservice.Config{
			Issuer:                    issuer,
			GroupScopes:               fileConfig.GroupScopes, // Keep for backward compatibility
			ClusterID:                 clusterID,
			OpenCHAMIID:               openCHAMIID,
			NonEnforcing:              nonEnforcing,
			EnableLocalUserMint:       enableLocalUserMint,
			OIDCIssuerURL:             oidcIssuerURL,
			OIDCClientID:              oidcClientID,
			OIDCClientSecret:          oidcClientSecret,
			RFC8693BootstrapStorePath: rfc8693BootstrapStorePath,
			RFC8693RefreshStorePath:   rfc8693RefreshStorePath,
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
		service, err := tokenservice.NewTokenService(keyManager, serviceConfig)
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
	serveCmd.Flags().BoolVar(&enableLocalUserMint, "enable-local-user-mint", false, "Enable local user-token mint mode (break-glass path)")

	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVar(&rfc8693BootstrapStorePath, "rfc8693-bootstrap-store", "", "Path to RFC 8693 bootstrap token store (or set TOKENSMITH_RFC8693_BOOTSTRAP_STORE; default: ./data/bootstrap-tokens)")
	serveCmd.Flags().StringVar(&rfc8693RefreshStorePath, "rfc8693-refresh-store", "", "Path to RFC 8693 refresh token family store (or set TOKENSMITH_RFC8693_REFRESH_STORE; default: ./data/refresh-tokens)")

	rootCmd.AddCommand(serveCmd)
}
