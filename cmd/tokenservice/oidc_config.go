// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var (
	oidcAdminURL          string
	oidcConfigureIssuer   string
	oidcConfigureClientID string
	oidcReplaceExisting   bool
	oidcDryRun            bool
)

var oidcCmd = &cobra.Command{
	Use:   "oidc",
	Short: "Manage OIDC configuration for a running local TokenSmith",
}

var oidcStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active runtime OIDC provider state",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := http.Get(strings.TrimRight(oidcAdminURL, "/") + "/admin/oidc/config")
		if err != nil {
			return fmt.Errorf("failed to query OIDC status: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var out tokenservice.OIDCConfigResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return fmt.Errorf("failed to parse status response: %w", err)
		}

		fmt.Printf("Configured: %t\n", out.OIDC.Configured)
		fmt.Printf("Issuer URL: %s\n", out.OIDC.IssuerURL)
		fmt.Printf("Client ID: %s\n", out.OIDC.ClientID)
		fmt.Printf("Local User Mint Enabled: %t\n", out.OIDC.LocalUserMintEnabled)
		return nil
	},
}

var oidcConfigureCmd = &cobra.Command{
	Use:   "configure",
	Short: "Configure the single OIDC provider for a running local TokenSmith",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(oidcConfigureIssuer) == "" {
			return fmt.Errorf("--issuer-url is required")
		}
		if strings.TrimSpace(oidcConfigureClientID) == "" {
			return fmt.Errorf("--client-id is required")
		}

		payload := tokenservice.OIDCConfigRequest{
			IssuerURL:       oidcConfigureIssuer,
			ClientID:        oidcConfigureClientID,
			ReplaceExisting: oidcReplaceExisting,
			DryRun:          oidcDryRun,
		}

		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to encode request: %w", err)
		}

		resp, err := http.Post(strings.TrimRight(oidcAdminURL, "/")+"/admin/oidc/config", "application/json", bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("failed to apply OIDC config: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("configure request failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var out tokenservice.OIDCConfigResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return fmt.Errorf("failed to parse configure response: %w", err)
		}

		fmt.Printf("Status: %s\n", out.Status)
		fmt.Printf("Configured: %t\n", out.OIDC.Configured)
		fmt.Printf("Issuer URL: %s\n", out.OIDC.IssuerURL)
		fmt.Printf("Client ID: %s\n", out.OIDC.ClientID)
		return nil
	},
}

func init() {
	oidcCmd.PersistentFlags().StringVar(&oidcAdminURL, "url", "http://127.0.0.1:8080", "Local TokenSmith URL")

	oidcConfigureCmd.Flags().StringVar(&oidcConfigureIssuer, "issuer-url", "", "OIDC issuer URL")
	oidcConfigureCmd.Flags().StringVar(&oidcConfigureClientID, "client-id", "", "OIDC client ID")
	oidcConfigureCmd.Flags().BoolVar(&oidcReplaceExisting, "replace-existing", false, "Replace an existing configured OIDC provider")
	oidcConfigureCmd.Flags().BoolVar(&oidcDryRun, "dry-run", false, "Validate and report create/replace outcome without applying changes")

	oidcCmd.AddCommand(oidcStatusCmd)
	oidcCmd.AddCommand(oidcConfigureCmd)
	rootCmd.AddCommand(oidcCmd)
}
