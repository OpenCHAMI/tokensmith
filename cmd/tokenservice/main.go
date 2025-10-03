// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"

	"github.com/openchami/tokensmith/pkg/policy"
	tokenservice "github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var (
	issuer           string
	port             int
	clusterID        string
	openCHAMIID      string
	oidcIssuerURL    string
	oidcClientID     string
	oidcClientSecret string
	configPath       string
	keyFile          string
	keyDir           string
	nonEnforcing     bool // Skip validation checks and only log errors
	// Policy engine configuration
	policyEngineType string
	policyConfigPath string
)

var rootCmd = &cobra.Command{
	Use:   "tokensmith",
	Short: "TokenSmith - Token Exchange Service",
	Long:  `TokenSmith provides token exchange and validation services for OpenCHAMI with pluggable policy engines for determining scopes, audiences, and permissions.`,
}

var generateConfigCmd = &cobra.Command{
	Use:   "generate-config",
	Short: "Generate a default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		config := tokenservice.DefaultFileConfig()
		if err := tokenservice.SaveFileConfig(config, configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Printf("Generated configuration file at: %s\n", configPath)
		return nil
	},
}

var generatePolicyConfigCmd = &cobra.Command{
	Use:   "generate-policy-config",
	Short: "Generate a default policy configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		policyConfig := &policy.FileBasedConfig{
			Version: "1.0.0",
			DefaultPolicy: &policy.PolicyDecision{
				Scopes:      []string{"read"},
				Audiences:   []string{"smd", "bss", "cloud-init"},
				Permissions: []string{"read:basic"},
			},
			Roles: map[string]*policy.RolePolicy{
				"admin": {
					Name:        "Administrator",
					Description: "Full administrative access",
					Scopes:      []string{"read", "write", "admin"},
					Audiences:   []string{"smd", "bss", "cloud-init", "admin-service"},
					Permissions: []string{"read:all", "write:all", "admin:all"},
				},
				"user": {
					Name:        "Regular User",
					Description: "Basic user access",
					Scopes:      []string{"read"},
					Audiences:   []string{"smd", "bss", "cloud-init"},
					Permissions: []string{"read:basic"},
				},
			},
			UserRoleMappings: map[string][]string{
				"adminuser":   {"admin"},
				"regularuser": {"user"},
			},
			GroupRoleMappings: map[string][]string{
				"admins": {"admin"},
				"users":  {"user"},
			},
		}

		if err := policy.SaveFileBasedConfig(policyConfig, policyConfigPath); err != nil {
			return fmt.Errorf("failed to save policy config: %w", err)
		}
		fmt.Printf("Generated policy configuration file at: %s\n", policyConfigPath)
		return nil
	},
}

func init() {

	rootCmd.AddCommand(generateConfigCmd)
	rootCmd.AddCommand(generatePolicyConfigCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to configuration file")
	rootCmd.PersistentFlags().StringVar(&policyConfigPath, "policy-config", "", "Path to policy configuration file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
