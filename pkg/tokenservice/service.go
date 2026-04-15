// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
)

type contextKey string

const (
	ScopeContextKey         contextKey = "scope"
	TargetServiceContextKey contextKey = "target_service"
)

// Config holds the configuration for the token service
type Config struct {
	Issuer              string
	GroupScopes         map[string][]string
	ClusterID           string
	OpenCHAMIID         string
	NonEnforcing        bool // Skip validation checks and only log errors
	EnableLocalUserMint bool

	// RFC 8693 stores (opaque token and family management)
	RFC8693BootstrapStorePath string
	RFC8693RefreshStorePath   string

	// OIDC provider configuration
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
}

// OIDCProviderConfigUpdate captures mutable single-provider OIDC settings.
type OIDCProviderConfigUpdate struct {
	IssuerURL       string
	ClientID        string
	ReplaceExisting bool
	DryRun          bool
}

// OIDCConfigRequest is the HTTP payload used to apply runtime OIDC updates.
type OIDCConfigRequest struct {
	IssuerURL       string `json:"issuer_url"`
	ClientID        string `json:"client_id"`
	ReplaceExisting bool   `json:"replace_existing"`
	DryRun          bool   `json:"dry_run"`
}

// OIDCProviderStatus describes current runtime OIDC provider state.
type OIDCProviderStatus struct {
	Configured           bool   `json:"configured"`
	IssuerURL            string `json:"issuer_url"`
	ClientID             string `json:"client_id"`
	LocalUserMintEnabled bool   `json:"local_user_mint_enabled"`
}

// OIDCConfigResponse is the HTTP response payload for runtime OIDC status/apply endpoints.
type OIDCConfigResponse struct {
	Status string             `json:"status"`
	OIDC   OIDCProviderStatus `json:"oidc"`
}

// TokenService handles token operations and provider interactions
type TokenService struct {
	TokenManager *token.TokenManager
	Config       Config
	Issuer       string
	GroupScopes  map[string][]string
	ClusterID    string
	OpenCHAMIID  string
	OIDCProvider oidc.Provider
	mu           sync.RWMutex

	// RFC 8693 stores for opaque bootstrap and refresh token families
	bootstrapTokenStore *BootstrapTokenStore
	refreshTokenStore   *RefreshTokenStore

	// Phase 3: per-IP rate limiting for failed bootstrap exchanges
	// (NIST SP 800-63-4 Section 5.2.2)
	replayLimiter *replayLimiter
}

// NewTokenService creates a new TokenService instance
func NewTokenService(keyManager *keys.KeyManager, config Config) (*TokenService, error) {
	// Initialize the token manager
	tokenManager := token.NewTokenManager(
		keyManager,
		config.Issuer,
		config.ClusterID,
		config.OpenCHAMIID,
		!config.NonEnforcing, // Enforce claims validation
	)

	// Initialize the simplified OIDC provider
	oidcProvider := oidc.NewSimpleProvider(
		config.OIDCIssuerURL,
		config.OIDCClientID,
		config.OIDCClientSecret,
	)

	svc := &TokenService{
		TokenManager:  tokenManager,
		Config:        config,
		Issuer:        config.Issuer,
		GroupScopes:   config.GroupScopes,
		ClusterID:     config.ClusterID,
		OpenCHAMIID:   config.OpenCHAMIID,
		OIDCProvider:  oidcProvider,
		replayLimiter: newReplayLimiter(),
	}

	// Initialize RFC 8693 stores for opaque bootstrap and refresh tokens
	// Initialize RFC 8693 stores for opaque bootstrap and refresh tokens
	// Use temp directories if paths not provided (for tests)
	bootstrapStorePath := config.RFC8693BootstrapStorePath
	if bootstrapStorePath == "" {
		var err error
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
		var err error
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

func (s *TokenService) currentOIDCProvider() oidc.Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.OIDCProvider
}

func (s *TokenService) hasConfiguredOIDCProvider() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return strings.TrimSpace(s.Config.OIDCIssuerURL) != "" && strings.TrimSpace(s.Config.OIDCClientID) != ""
}

// GetOIDCProviderStatus returns current in-memory OIDC provider status.
func (s *TokenService) GetOIDCProviderStatus() OIDCProviderStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return OIDCProviderStatus{
		Configured:           strings.TrimSpace(s.Config.OIDCIssuerURL) != "" && strings.TrimSpace(s.Config.OIDCClientID) != "",
		IssuerURL:            s.Config.OIDCIssuerURL,
		ClientID:             s.Config.OIDCClientID,
		LocalUserMintEnabled: s.Config.EnableLocalUserMint,
	}
}

// ApplyOIDCProviderConfig updates the active single OIDC provider in memory.
func (s *TokenService) ApplyOIDCProviderConfig(ctx context.Context, update OIDCProviderConfigUpdate) (string, OIDCProviderStatus, error) {
	issuerURL := strings.TrimSpace(update.IssuerURL)
	clientID := strings.TrimSpace(update.ClientID)
	if issuerURL == "" {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("issuer_url is required")
	}
	if clientID == "" {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("client_id is required")
	}

	secret := strings.TrimSpace(s.Config.OIDCClientSecret)
	if secret == "" {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("OIDC client secret is not configured in service environment")
	}

	hasExisting := s.hasConfiguredOIDCProvider()
	if hasExisting && !update.ReplaceExisting {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("OIDC provider already configured; use --replace-existing to overwrite")
	}

	provider := oidc.NewSimpleProvider(issuerURL, clientID, secret)
	if _, err := provider.GetProviderMetadata(ctx); err != nil {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("OIDC provider validation failed: %w", err)
	}

	status := s.GetOIDCProviderStatus()
	if update.DryRun {
		if hasExisting {
			return "would_replace", status, nil
		}
		return "would_create", status, nil
	}

	s.mu.Lock()
	s.OIDCProvider = provider
	s.Config.OIDCIssuerURL = issuerURL
	s.Config.OIDCClientID = clientID
	s.mu.Unlock()

	if hasExisting {
		return "replaced", s.GetOIDCProviderStatus(), nil
	}
	return "created", s.GetOIDCProviderStatus(), nil
}
