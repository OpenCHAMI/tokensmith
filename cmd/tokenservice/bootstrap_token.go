// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tokenservice "github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap-token",
	Short: "Manage bootstrap tokens (RFC 8693)",
	Long:  `Create and manage one-time-use bootstrap tokens for service initialization per RFC 8693`,
}

var createBootstrapCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new opaque bootstrap token",
	Long: `Create a new RFC 8693 bootstrap token with server-side policy.

The token is generated as an opaque, cryptographically-secure random value (256 bits).
Server-side policy includes immutable scopes, audience, and TTL.

Example:
  tokensmith bootstrap-token create \
    --subject boot-service \
    --audience hsm \
    --scopes "node:read,node:write" \
    --ttl 10m \
    --refresh-ttl 24h \
    --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get parameters from flags
		subject, _ := cmd.Flags().GetString("subject")
		audience, _ := cmd.Flags().GetString("audience")
		scopesStr, _ := cmd.Flags().GetString("scopes")
		ttlStr, _ := cmd.Flags().GetString("ttl")
		refreshTTLStr, _ := cmd.Flags().GetString("refresh-ttl")
		bindingID, _ := cmd.Flags().GetString("binding-identifier")
		outputFormat, _ := cmd.Flags().GetString("output-format")
		storePath, _ := cmd.Flags().GetString("bootstrap-store")

		// Validate required parameters
		if subject == "" {
			return fmt.Errorf("--subject is required")
		}
		if audience == "" {
			return fmt.Errorf("--audience is required")
		}

		// Parse scopes
		var scopes []string
		if scopesStr != "" {
			scopes = strings.FieldsFunc(scopesStr, func(r rune) bool {
				return r == ',' || r == ' '
			})
		}

		// Parse TTLs
		ttl, err := time.ParseDuration(ttlStr)
		if err != nil {
			return fmt.Errorf("invalid TTL duration: %w", err)
		}
		if ttl < time.Minute || ttl > time.Hour {
			return fmt.Errorf("TTL must be between 1 minute and 1 hour (got %v)", ttl)
		}

		refreshTTL, err := time.ParseDuration(refreshTTLStr)
		if err != nil {
			return fmt.Errorf("invalid refresh TTL duration: %w", err)
		}
		if refreshTTL < time.Hour || refreshTTL > 30*24*time.Hour {
			return fmt.Errorf("refresh TTL must be between 1 hour and 30 days (got %v)", refreshTTL)
		}

		// Use provided store path or temp directory
		if storePath == "" {
			storePath, err = os.MkdirTemp("", "tokensmith-bootstrap-*")
			if err != nil {
				return fmt.Errorf("failed to create temp store: %w", err)
			}
		}

		// Create bootstrap token store
		store, err := tokenservice.NewBootstrapTokenStore(storePath)
		if err != nil {
			return fmt.Errorf("failed to initialize bootstrap token store: %w", err)
		}

		// Generate opaque token (256 bits = 32 bytes)
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			return fmt.Errorf("failed to generate random token: %w", err)
		}
		opaqueToken := hex.EncodeToString(tokenBytes)

		// Create policy
		now := time.Now()
		policy := &tokenservice.BootstrapTokenPolicy{
			ID:                fmt.Sprintf("bt-%d", now.UnixNano()),
			TokenHash:         tokenservice.HashBootstrapToken(opaqueToken),
			Subject:           subject,
			Audience:          audience,
			Scopes:            scopes,
			TTL:               ttl,
			RefreshTTL:        refreshTTL,
			CreatedAt:         now,
			ExpiresAt:         now.Add(ttl),
			BindingIdentifier: bindingID,
		}

		// Store policy
		if err := store.SavePolicy(policy); err != nil {
			return fmt.Errorf("failed to save policy: %w", err)
		}

		// Output token and metadata
		switch outputFormat {
		case "json":
			output := map[string]interface{}{
				"bootstrap_token": opaqueToken,
				"expires_at":      policy.ExpiresAt.Format(time.RFC3339),
				"policy": map[string]interface{}{
					"subject":             policy.Subject,
					"audience":            policy.Audience,
					"scopes":              policy.Scopes,
					"ttl_seconds":         int(policy.TTL.Seconds()),
					"refresh_ttl_seconds": int(policy.RefreshTTL.Seconds()),
					"binding_identifier":  policy.BindingIdentifier,
				},
			}
			jsonBytes, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(jsonBytes))

		case "text":
			fmt.Printf("Bootstrap Token:  %s\n", opaqueToken)
			fmt.Printf("Expires At:       %s\n", policy.ExpiresAt.Format(time.RFC3339))
			fmt.Printf("Subject:          %s\n", policy.Subject)
			fmt.Printf("Audience:         %s\n", policy.Audience)
			fmt.Printf("Scopes:           %s\n", strings.Join(policy.Scopes, ", "))
			fmt.Printf("TTL:              %s\n", policy.TTL)
			fmt.Printf("Refresh TTL:      %s\n", policy.RefreshTTL)
			if bindingID != "" {
				fmt.Printf("Binding ID:       %s\n", bindingID)
			}

		default:
			return fmt.Errorf("unknown output format: %s", outputFormat)
		}

		// Store path information
		fmt.Fprintf(os.Stderr, "\n✓ Bootstrap token created successfully\n")
		fmt.Fprintf(os.Stderr, "  Store path: %s\n", storePath)
		fmt.Fprintf(os.Stderr, "  Token hash: %s\n", policy.TokenHash[:16]+"...")

		return nil
	},
}

func init() {
	// Create command flags
	createBootstrapCmd.Flags().StringVar(&subject, "subject", "", "Service requesting access (e.g., boot-service)")
	createBootstrapCmd.Flags().StringVar(&audience, "audience", "", "Target service (e.g., hsm, smd)")
	createBootstrapCmd.Flags().StringVar(
		&scopesStr, "scopes", "",
		"Comma or space-separated scopes (e.g., 'node:read,node:write')",
	)
	createBootstrapCmd.Flags().StringVar(
		&ttlStr, "ttl", "10m",
		"Bootstrap token lifetime (min: 1m, max: 1h)",
	)
	createBootstrapCmd.Flags().StringVar(
		&refreshTTLStr, "refresh-ttl", "24h",
		"Max lifetime for issued refresh tokens (min: 1h, max: 30d)",
	)
	createBootstrapCmd.Flags().StringVar(
		&bindingID, "binding-identifier", "",
		"Optional audit context (pod ID, instance ID, deployment ID)",
	)
	createBootstrapCmd.Flags().StringVar(
		&outputFormat, "output-format", "text",
		"Output format (json or text)",
	)
	createBootstrapCmd.Flags().StringVar(
		&storePath, "bootstrap-store", "",
		"Path to bootstrap token store (default: temp directory)",
	)

	// Mark required flags
	if err := createBootstrapCmd.MarkFlagRequired("subject"); err != nil {
		panic(err)
	}
	if err := createBootstrapCmd.MarkFlagRequired("audience"); err != nil {
		panic(err)
	}

	bootstrapCmd.AddCommand(createBootstrapCmd)
	rootCmd.AddCommand(bootstrapCmd)
}

// Flag variables for bootstrap token creation
var (
	subject       string
	audience      string
	scopesStr     string
	ttlStr        string
	refreshTTLStr string
	bindingID     string
	outputFormat  string
	storePath     string
)
