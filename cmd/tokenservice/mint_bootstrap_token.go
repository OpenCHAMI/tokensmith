// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var (
	mintBootstrapServiceID   string
	mintBootstrapTarget      string
	mintBootstrapScopes      string
	mintBootstrapTTL         time.Duration
	mintBootstrapIssuer      string
	mintBootstrapClusterID   string
	mintBootstrapOpenCHAMIID string
	mintBootstrapPrivateKey  string
)

var mintBootstrapTokenCmd = &cobra.Command{
	Use:   "mint-bootstrap-token",
	Short: "Mint a one-time bootstrap token for service startup",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(mintBootstrapPrivateKey) == "" {
			return fmt.Errorf("--key-file is required")
		}
		if strings.TrimSpace(mintBootstrapServiceID) == "" {
			return fmt.Errorf("--service-id is required")
		}
		if strings.TrimSpace(mintBootstrapTarget) == "" {
			return fmt.Errorf("--target-service is required")
		}
		if mintBootstrapTTL <= 0 {
			return fmt.Errorf("--ttl must be greater than zero")
		}

		keyManager := keys.NewKeyManager()
		if err := keyManager.LoadPrivateKey(mintBootstrapPrivateKey); err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		svc, err := tokenservice.NewTokenService(keyManager, tokenservice.Config{
			Issuer:      mintBootstrapIssuer,
			ClusterID:   mintBootstrapClusterID,
			OpenCHAMIID: mintBootstrapOpenCHAMIID,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize token service: %w", err)
		}

		scopes := parseScopeCSV(mintBootstrapScopes)
		bootstrapToken, err := svc.MintBootstrapToken(cmd.Context(), mintBootstrapServiceID, mintBootstrapTarget, scopes, mintBootstrapTTL)
		if err != nil {
			return fmt.Errorf("failed to mint bootstrap token: %w", err)
		}

		fmt.Println(bootstrapToken)
		return nil
	},
}

func parseScopeCSV(scopesCSV string) []string {
	if strings.TrimSpace(scopesCSV) == "" {
		return nil
	}

	scopes := strings.Split(scopesCSV, ",")
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		out = append(out, scope)
	}
	return out
}

func init() {
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapPrivateKey, "key-file", "", "Path to RSA private key file used for signing")
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapServiceID, "service-id", "", "Caller service identity to embed in subject")
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapTarget, "target-service", "", "Target service audience allowed by the bootstrap token")
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapScopes, "scopes", "", "Comma-separated scopes allowed for service token exchange")
	mintBootstrapTokenCmd.Flags().DurationVar(&mintBootstrapTTL, "ttl", 5*time.Minute, "Bootstrap token lifetime")
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapIssuer, "issuer", "http://tokensmith:8080", "Bootstrap token issuer")
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapClusterID, "cluster-id", "cl-F00F00F00", "Cluster identifier claim")
	mintBootstrapTokenCmd.Flags().StringVar(&mintBootstrapOpenCHAMIID, "openchami-id", "oc-F00F00F00", "OpenCHAMI identifier claim")

	rootCmd.AddCommand(mintBootstrapTokenCmd)
}
