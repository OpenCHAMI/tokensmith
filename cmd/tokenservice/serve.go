// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the token service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if configPath == "" {
			configPath = os.Getenv("TOKENSMITH_CONFIG")
		}

		// Load configuration
		fileConfig, err := tokenservice.LoadFileConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Get service identity settings from environment variables if not
		// provided via flags. These flags carry non-empty defaults, so the
		// flag must be checked for explicit use rather than for emptiness.
		envFallback(cmd, "issuer", "TOKENSMITH_ISSUER", &issuer)
		envFallback(cmd, "cluster-id", "TOKENSMITH_CLUSTER_ID", &clusterID)
		envFallback(cmd, "openchami-id", "TOKENSMITH_OPENCHAMI_ID", &openCHAMIID)
		envFallback(cmd, "oidc-issuer", "TOKENSMITH_OIDC_PROVIDER", &oidcIssuerURL)
		if !cmd.Flags().Changed("port") {
			if value := strings.TrimSpace(os.Getenv("TOKENSMITH_PORT")); value != "" {
				parsed, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Errorf("invalid TOKENSMITH_PORT %q: %w", value, err)
				}
				port = parsed
			}
		}
		if keyDir == "" {
			keyDir = os.Getenv("TOKENSMITH_KEY_DIR")
		}
		if strings.TrimSpace(issuer) == "" {
			return fmt.Errorf("issuer is required: set --issuer or TOKENSMITH_ISSUER")
		}
		if strings.TrimSpace(oidcIssuerURL) == "" {
			return fmt.Errorf("OIDC issuer is required: set --oidc-issuer or TOKENSMITH_OIDC_PROVIDER")
		}

		// Get OIDC credentials from environment variables if not provided via flags
		if oidcClientID == "" {
			oidcClientID = os.Getenv("OIDC_CLIENT_ID")
		}
		if oidcClientSecret == "" {
			oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
		}
		envFallback(cmd, "oidc-introspection-endpoint", "TOKENSMITH_OIDC_INTROSPECTION_ENDPOINT", &oidcIntrospectionEndpoint)
		if oidcClaimPolicy == "" {
			oidcClaimPolicy = os.Getenv("TOKENSMITH_OIDC_CLAIM_POLICY")
		}
		if oidcCAPath == "" {
			oidcCAPath = os.Getenv("TOKENSMITH_OIDC_CA")
		}
		exchangeSessionLifetime := fileConfig.MaxExchangeSessionLifetime
		if envLifetime := os.Getenv("TOKENSMITH_MAX_EXCHANGE_SESSION_LIFETIME"); envLifetime != "" {
			exchangeSessionLifetime = envLifetime
		}
		if maxExchangeSessionLifetime != "" {
			exchangeSessionLifetime = maxExchangeSessionLifetime
		}
		maxExchangeLifetime, err := tokenservice.ParseMaxExchangeSessionLifetime(exchangeSessionLifetime)
		if err != nil {
			return err
		}
		claimPolicy, err := tokenservice.ParseOIDCClaimPolicy(oidcClaimPolicy)
		if err != nil {
			return err
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
		if serviceIdentityCAPath == "" {
			serviceIdentityCAPath = os.Getenv("TOKENSMITH_SERVICE_IDENTITY_CA")
		}
		if tlsCertFile == "" {
			tlsCertFile = os.Getenv("TOKENSMITH_TLS_CERT_FILE")
		}
		if tlsKeyFile == "" {
			tlsKeyFile = os.Getenv("TOKENSMITH_TLS_KEY_FILE")
		}

		// Create token service configuration
		serviceConfig := tokenservice.Config{
			Issuer:                     issuer,
			GroupScopes:                fileConfig.GroupScopes, // Keep for backward compatibility
			ClusterID:                  clusterID,
			OpenCHAMIID:                openCHAMIID,
			NonEnforcing:               nonEnforcing,
			EnableLocalUserMint:        enableLocalUserMint,
			OIDCIssuerURL:              oidcIssuerURL,
			OIDCClientID:               oidcClientID,
			OIDCClientSecret:           oidcClientSecret,
			OIDCIntrospectionEndpoint:  oidcIntrospectionEndpoint,
			OIDCClaimPolicy:            claimPolicy,
			OIDCCAPath:                 oidcCAPath,
			MaxExchangeSessionLifetime: maxExchangeLifetime,
			RFC8693BootstrapStorePath:  rfc8693BootstrapStorePath,
			RFC8693RefreshStorePath:    rfc8693RefreshStorePath,
			ServiceIdentityCAPath:      serviceIdentityCAPath,
			TLSCertFile:                tlsCertFile,
			TLSKeyFile:                 tlsKeyFile,
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

// envFallback applies the value of env to target when flag was not explicitly
// provided on the command line. Flags with non-empty defaults cannot use the
// emptiness check other environment fallbacks in this file rely on.
func envFallback(cmd *cobra.Command, flag, env string, target *string) {
	if cmd.Flags().Changed(flag) {
		return
	}
	if value := strings.TrimSpace(os.Getenv(env)); value != "" {
		*target = value
	}
}

func init() {
	// Serve command flags
	serveCmd.Flags().StringVar(&issuer, "issuer", "", "Token issuer identifier (required; or set TOKENSMITH_ISSUER)")
	serveCmd.Flags().IntVar(&port, "port", 8080, "HTTP server port")
	serveCmd.Flags().StringVar(&clusterID, "cluster-id", "cl-F00F00F00", "Unique identifier for this cluster")
	serveCmd.Flags().StringVar(&openCHAMIID, "openchami-id", "oc-F00F00F00", "Unique identifier for this instance of OpenCHAMI")
	serveCmd.Flags().StringVar(&oidcIssuerURL, "oidc-issuer", "", "OIDC provider issuer URL (required; or set TOKENSMITH_OIDC_PROVIDER)")
	serveCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", "", "OIDC client ID (or set OIDC_CLIENT_ID env var)")
	serveCmd.Flags().StringVar(&oidcClientSecret, "oidc-client-secret", "", "OIDC client secret (or set OIDC_CLIENT_SECRET env var)")
	serveCmd.Flags().StringVar(&oidcIntrospectionEndpoint, "oidc-introspection-endpoint", "", "OIDC token introspection endpoint override (or set TOKENSMITH_OIDC_INTROSPECTION_ENDPOINT)")
	serveCmd.Flags().StringVar(&oidcClaimPolicy, "oidc-claim-policy", "", "OIDC claim policy: enriched or csm-keycloak (or set TOKENSMITH_OIDC_CLAIM_POLICY)")
	serveCmd.Flags().StringVar(&oidcCAPath, "oidc-ca", "", "Path to PEM CA bundle trusted for upstream OIDC TLS (or set TOKENSMITH_OIDC_CA)")
	serveCmd.Flags().StringVar(&maxExchangeSessionLifetime, "max-exchange-session-lifetime", "", "Maximum TokenSmith session lifetime for exchanged OIDC tokens, e.g. 24h or 168h (or set TOKENSMITH_MAX_EXCHANGE_SESSION_LIFETIME)")
	serveCmd.Flags().StringVar(&keyFile, "key-file", "", "Path to private key file")
	serveCmd.Flags().StringVar(&keyDir, "key-dir", "", "Directory to save key files")
	serveCmd.Flags().BoolVar(&nonEnforcing, "non-enforcing", false, "Skip validation checks and only log errors")
	serveCmd.Flags().BoolVar(&enableLocalUserMint, "enable-local-user-mint", false, "Enable local user-token mint mode (break-glass path)")
	serveCmd.Flags().StringVar(&serviceIdentityCAPath, "service-identity-ca", "", "Path to PEM CA bundle trusted for inbound service identity client certificates (or set TOKENSMITH_SERVICE_IDENTITY_CA)")
	serveCmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", "", "Path to TLS server certificate PEM (or set TOKENSMITH_TLS_CERT_FILE)")
	serveCmd.Flags().StringVar(&tlsKeyFile, "tls-key-file", "", "Path to TLS server private key PEM (or set TOKENSMITH_TLS_KEY_FILE)")

	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVar(&rfc8693BootstrapStorePath, "rfc8693-bootstrap-store", "", "Path to RFC 8693 bootstrap token store (or set TOKENSMITH_RFC8693_BOOTSTRAP_STORE; default: ./data/bootstrap-tokens)")
	serveCmd.Flags().StringVar(&rfc8693RefreshStorePath, "rfc8693-refresh-store", "", "Path to RFC 8693 refresh token family store (or set TOKENSMITH_RFC8693_REFRESH_STORE; default: ./data/refresh-tokens)")
}
