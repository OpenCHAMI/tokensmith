// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"fmt"
	"os"
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
	Issuer       string
	GroupScopes  map[string][]string
	ClusterID    string
	OpenCHAMIID  string
	NonEnforcing bool // Skip validation checks and only log errors

	// RFC 8693 stores (opaque token and family management)
	RFC8693BootstrapStorePath string
	RFC8693RefreshStorePath   string

	// OIDC provider configuration
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
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
