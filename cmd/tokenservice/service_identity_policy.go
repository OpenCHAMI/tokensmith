// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

const defaultServiceIdentityPolicyStorePath = "./data/service-identities"

func newServiceIdentityPolicyCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "service-identity-policy",
		Short: "Manage mTLS service identity authorization policies",
	}
	command.AddCommand(newCreateServiceIdentityPolicyCmd(), newRevokeServiceIdentityPolicyCmd(), newListServiceIdentityPolicyCmd())
	return command
}

func newCreateServiceIdentityPolicyCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "create",
		Short: "Create a dedicated mTLS service identity policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			subject, err := cmd.Flags().GetString("subject")
			if err != nil {
				return err
			}
			audience, err := cmd.Flags().GetString("audience")
			if err != nil {
				return err
			}
			scopesCSV, err := cmd.Flags().GetString("scopes")
			if err != nil {
				return err
			}
			policyTTLValue, err := cmd.Flags().GetString("ttl")
			if err != nil {
				return err
			}
			refreshTTLValue, err := cmd.Flags().GetString("refresh-ttl")
			if err != nil {
				return err
			}
			storePath, err := resolveServiceIdentityPolicyStorePath(cmd)
			if err != nil {
				return err
			}
			policyTTL, err := time.ParseDuration(policyTTLValue)
			if err != nil || policyTTL <= 0 {
				return fmt.Errorf("--ttl must be a positive duration")
			}
			refreshTTL, err := time.ParseDuration(refreshTTLValue)
			if err != nil || refreshTTL <= 0 {
				return fmt.Errorf("--refresh-ttl must be a positive duration")
			}
			if refreshTTL > policyTTL {
				return fmt.Errorf("--refresh-ttl must not exceed --ttl")
			}
			scopes := ParseScopeCSV(scopesCSV)
			if len(scopes) == 0 {
				return fmt.Errorf("--scopes is required")
			}
			store, err := tokenservice.NewServiceIdentityPolicyStore(storePath)
			if err != nil {
				return fmt.Errorf("initialize service identity policy store: %w", err)
			}
			now := time.Now().UTC()
			policy := &tokenservice.ServiceIdentityPolicy{
				Version:    tokenservice.ServiceIdentityPolicyVersion,
				ID:         fmt.Sprintf("sip-%d", now.UnixNano()),
				Subject:    strings.TrimSpace(subject),
				Audience:   strings.TrimSpace(audience),
				Scopes:     scopes,
				RefreshTTL: refreshTTL,
				CreatedAt:  now,
				ExpiresAt:  now.Add(policyTTL),
			}
			if err := store.Create(policy); err != nil {
				return fmt.Errorf("create service identity policy: %w", err)
			}
			return writeServiceIdentityPolicyMetadata(cmd, []tokenservice.ServiceIdentityPolicy{*policy})
		},
	}
	addServiceIdentityPolicyStoreFlag(command)
	command.Flags().String("subject", "", "mTLS certificate subject common name")
	command.Flags().String("audience", "", "authorized token audience")
	command.Flags().String("scopes", "", "comma- or whitespace-separated authorized scopes")
	command.Flags().String("ttl", "", "policy lifetime")
	command.Flags().String("refresh-ttl", "", "refresh family lifetime")
	for _, name := range []string{"subject", "audience", "scopes", "ttl", "refresh-ttl"} {
		if err := command.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
	return command
}

func newRevokeServiceIdentityPolicyCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a dedicated mTLS service identity policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			subject, err := cmd.Flags().GetString("subject")
			if err != nil {
				return err
			}
			storePath, err := resolveServiceIdentityPolicyStorePath(cmd)
			if err != nil {
				return err
			}
			store, err := tokenservice.NewServiceIdentityPolicyStore(storePath)
			if err != nil {
				return fmt.Errorf("initialize service identity policy store: %w", err)
			}
			if err := store.Revoke(subject, time.Now().UTC()); err != nil {
				return fmt.Errorf("revoke service identity policy: %w", err)
			}
			return nil
		},
	}
	addServiceIdentityPolicyStoreFlag(command)
	command.Flags().String("subject", "", "mTLS certificate subject common name")
	if err := command.MarkFlagRequired("subject"); err != nil {
		panic(err)
	}
	return command
}

func newListServiceIdentityPolicyCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List dedicated mTLS service identity authorization metadata",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			storePath, err := resolveServiceIdentityPolicyStorePath(cmd)
			if err != nil {
				return err
			}
			store, err := tokenservice.NewServiceIdentityPolicyStore(storePath)
			if err != nil {
				return fmt.Errorf("initialize service identity policy store: %w", err)
			}
			policies, err := store.List()
			if err != nil {
				return fmt.Errorf("list service identity policies: %w", err)
			}
			return writeServiceIdentityPolicyMetadata(cmd, policies)
		},
	}
	addServiceIdentityPolicyStoreFlag(command)
	return command
}

func addServiceIdentityPolicyStoreFlag(command *cobra.Command) {
	command.Flags().String("service-identity-policy-store", defaultServiceIdentityPolicyStorePath, "path to service identity policy store (or set TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE; default: ./data/service-identities)")
}

func writeServiceIdentityPolicyMetadata(command *cobra.Command, policies []tokenservice.ServiceIdentityPolicy) error {
	type metadata struct {
		Subject   string     `json:"subject"`
		Audience  string     `json:"audience"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt time.Time  `json:"expires_at"`
		RevokedAt *time.Time `json:"revoked_at,omitempty"`
	}
	output := make([]metadata, 0, len(policies))
	for _, policy := range policies {
		output = append(output, metadata{
			Subject:   policy.Subject,
			Audience:  policy.Audience,
			Scopes:    append([]string(nil), policy.Scopes...),
			ExpiresAt: policy.ExpiresAt,
			RevokedAt: policy.RevokedAt,
		})
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("encode service identity policy metadata: %w", err)
	}
	_, err = fmt.Fprintln(command.OutOrStdout(), string(encoded))
	return err
}

func init() {
	rootCmd.AddCommand(newServiceIdentityPolicyCmd())
}
