// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/spf13/cobra"
)

var (
	userTokenKeyFile             string
	userTokenSubject             string
	userTokenAudience            string
	userTokenScopes              string
	userTokenTTL                 time.Duration
	userTokenIssuer              string
	userTokenClusterID           string
	userTokenOpenCHAMIID         string
	userTokenEnableLocalUserMint bool
)

var userTokenCmd = &cobra.Command{
	Use:   "user-token",
	Short: "Create local user tokens for no-upstream OIDC scenarios",
}

var userTokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a local user token (break-glass path)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !userTokenEnableLocalUserMint {
			return fmt.Errorf("local user minting is disabled; re-run with --enable-local-user-mint")
		}
		if strings.TrimSpace(userTokenKeyFile) == "" {
			return fmt.Errorf("--key-file is required")
		}
		if strings.TrimSpace(userTokenSubject) == "" {
			return fmt.Errorf("--subject is required")
		}
		if strings.TrimSpace(userTokenAudience) == "" {
			return fmt.Errorf("--audience is required")
		}
		if userTokenTTL <= 0 {
			return fmt.Errorf("--ttl must be greater than zero")
		}

		scopes := ParseScopeCSV(userTokenScopes)
		if len(scopes) == 0 {
			return fmt.Errorf("--scopes must include at least one scope")
		}

		keyManager := keys.NewKeyManager()
		if err := keyManager.LoadPrivateKey(userTokenKeyFile); err != nil {
			return fmt.Errorf("failed to load private key: %w", err)
		}

		tm := token.NewTokenManager(keyManager, userTokenIssuer, userTokenClusterID, userTokenOpenCHAMIID, true)
		now := time.Now().UTC()
		claims := &token.TSClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    userTokenIssuer,
				Subject:   userTokenSubject,
				Audience:  []string{userTokenAudience},
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(userTokenTTL)),
			},
			Scope:       scopes,
			AuthLevel:   "IAL2",
			AuthFactors: 2,
			AuthMethods: []string{"local_user_mint", "operator_attested"},
			SessionID:   fmt.Sprintf("local-%d", now.UnixNano()),
			SessionExp:  now.Add(userTokenTTL).Unix(),
			AuthEvents:  []string{"local_user_token_mint"},
			ClusterID:   userTokenClusterID,
			OpenCHAMIID: userTokenOpenCHAMIID,
		}

		tok, err := tm.GenerateToken(claims)
		if err != nil {
			return fmt.Errorf("failed to generate user token: %w", err)
		}

		fmt.Println(tok)
		return nil
	},
}

func init() {
	userTokenCreateCmd.Flags().StringVar(&userTokenKeyFile, "key-file", "", "Path to RSA private key file used for signing")
	userTokenCreateCmd.Flags().StringVar(&userTokenSubject, "subject", "", "User subject claim")
	userTokenCreateCmd.Flags().StringVar(&userTokenAudience, "audience", "openchami", "Audience claim")
	userTokenCreateCmd.Flags().StringVar(&userTokenScopes, "scopes", "", "Comma-separated scopes")
	userTokenCreateCmd.Flags().DurationVar(&userTokenTTL, "ttl", time.Hour, "Token lifetime")
	userTokenCreateCmd.Flags().StringVar(&userTokenIssuer, "issuer", "http://tokensmith:8080", "Token issuer")
	userTokenCreateCmd.Flags().StringVar(&userTokenClusterID, "cluster-id", "cl-F00F00F00", "Cluster identifier claim")
	userTokenCreateCmd.Flags().StringVar(&userTokenOpenCHAMIID, "openchami-id", "oc-F00F00F00", "OpenCHAMI identifier claim")
	userTokenCreateCmd.Flags().BoolVar(&userTokenEnableLocalUserMint, "enable-local-user-mint", false, "Explicitly enable local user token minting (break-glass use only)")

	userTokenCmd.AddCommand(userTokenCreateCmd)
	rootCmd.AddCommand(userTokenCmd)
}
