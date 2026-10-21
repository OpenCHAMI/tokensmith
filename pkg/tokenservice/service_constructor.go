// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"fmt"
	"os"
	"strings"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
)

// NewTokenService creates a new TokenService instance.
func NewTokenService(keyManager *keys.KeyManager, config Config) (*TokenService, error) {
	claimPolicy, err := ParseOIDCClaimPolicy(string(config.OIDCClaimPolicy))
	if err != nil {
		return nil, err
	}
	config.OIDCClaimPolicy = claimPolicy
	providerMode, err := oidc.ParseProviderMode(string(config.OIDCProviderMode))
	if err != nil {
		return nil, err
	}
	config.OIDCProviderMode = providerMode
	if config.VaultUserInfoFallbackTTL == 0 {
		config.VaultUserInfoFallbackTTL = oidc.DefaultVaultUserInfoFallbackTTL
	}
	if err := oidc.ValidateVaultUserInfoFallbackTTL(config.VaultUserInfoFallbackTTL); err != nil {
		return nil, err
	}
	if providerMode == oidc.ProviderModeVault &&
		(strings.TrimSpace(config.OIDCIssuerURL) == "" || strings.TrimSpace(config.OIDCClientID) == "") {
		return nil, fmt.Errorf("vault provider mode requires OIDC issuer URL and client ID")
	}
	if config.MaxExchangeSessionLifetime == 0 {
		config.MaxExchangeSessionLifetime = DefaultMaxExchangeSessionLifetime
	}
	if config.MaxExchangeSessionLifetime < 0 {
		return nil, fmt.Errorf("max exchange session lifetime must be greater than zero")
	}
	oidcHTTPClient, err := newOIDCHTTPClient(config.OIDCCAPath)
	if err != nil {
		return nil, err
	}
	oidcOptions := []oidc.SimpleProviderOption{}
	if oidcHTTPClient != nil {
		oidcOptions = append(oidcOptions, oidc.WithHTTPClient(oidcHTTPClient))
	}
	if config.OIDCIntrospectionEndpoint != "" {
		oidcOptions = append(oidcOptions, oidc.WithIntrospectionEndpoint(config.OIDCIntrospectionEndpoint))
	}
	oidcOptions = append(oidcOptions,
		oidc.WithProviderMode(providerMode),
		oidc.WithVaultUserInfoFallbackTTL(config.VaultUserInfoFallbackTTL),
	)

	tokenManager := token.NewTokenManager(keyManager, config.Issuer, config.ClusterID, config.OpenCHAMIID, !config.NonEnforcing)
	oidcProvider := oidc.NewSimpleProvider(config.OIDCIssuerURL, config.OIDCClientID, config.OIDCClientSecret, oidcOptions...)
	svc := &TokenService{
		TokenManager:    tokenManager,
		Config:          config,
		Issuer:          config.Issuer,
		GroupScopes:     config.GroupScopes,
		ClusterID:       config.ClusterID,
		OpenCHAMIID:     config.OpenCHAMIID,
		OIDCProvider:    oidcProvider,
		replayLimiter:   newReplayLimiter(),
		revocationStore: NewRevocationStore(),
		oidcHTTPClient:  oidcHTTPClient,
	}
	if strings.TrimSpace(config.ServiceIdentityCAPath) != "" {
		caPool, err := loadCertPoolFromPEMFile(config.ServiceIdentityCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load service identity CA bundle: %w", err)
		}
		svc.serviceIdentityCAPool = caPool
	}
	serviceIdentityPolicyStorePath := config.ServiceIdentityPolicyStorePath
	if serviceIdentityPolicyStorePath == "" {
		serviceIdentityPolicyStorePath, err = os.MkdirTemp("", "tokensmith-service-identities-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp service identity policy store: %w", err)
		}
	}
	serviceIdentityPolicyStore, err := NewServiceIdentityPolicyStore(serviceIdentityPolicyStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize service identity policy store: %w", err)
	}
	svc.serviceIdentityPolicyStore = serviceIdentityPolicyStore
	bootstrapStorePath := config.RFC8693BootstrapStorePath
	if bootstrapStorePath == "" {
		bootstrapStorePath, err = os.MkdirTemp("", "tokensmith-bootstrap-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp bootstrap token store: %w", err)
		}
	}
	bootstrapStore, err := NewBootstrapTokenStore(bootstrapStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RFC 8693 bootstrap token store: %w", err)
	}
	svc.bootstrapTokenStore = bootstrapStore
	refreshStorePath := config.RFC8693RefreshStorePath
	if refreshStorePath == "" {
		refreshStorePath, err = os.MkdirTemp("", "tokensmith-refresh-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp refresh token store: %w", err)
		}
	}
	refreshStore, err := NewRefreshTokenStore(refreshStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RFC 8693 refresh token store: %w", err)
	}
	svc.refreshTokenStore = refreshStore
	return svc, nil
}
