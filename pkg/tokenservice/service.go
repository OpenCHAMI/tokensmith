// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
)

type contextKey string

const DefaultMaxExchangeSessionLifetime = 24 * time.Hour

const (
	ScopeContextKey         contextKey = "scope"
	TargetServiceContextKey contextKey = "target_service"
	socketPeerContextKey    contextKey = "socket_peer"
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

	// Service-identity mTLS trust anchor and TLS listener settings.
	ServiceIdentityCAPath          string
	ServiceIdentityPolicyStorePath string
	TLSCertFile                    string
	TLSKeyFile                     string

	// OIDC provider configuration
	OIDCIssuerURL              string
	OIDCClientID               string
	OIDCClientSecret           string
	OIDCIntrospectionEndpoint  string
	OIDCClaimPolicy            OIDCClaimPolicy
	OIDCProviderMode           oidc.ProviderMode
	OIDCCAPath                 string
	MaxExchangeSessionLifetime time.Duration
	VaultUserInfoFallbackTTL   time.Duration
}

// OIDCProviderConfigUpdate captures mutable single-provider OIDC settings.
type OIDCProviderConfigUpdate struct {
	IssuerURL                       string
	ClientID                        string
	ClaimPolicy                     string
	ProviderMode                    oidc.ProviderMode
	VaultUserInfoFallbackTTLSeconds int64
	ReplaceExisting                 bool
	DryRun                          bool
}

// OIDCConfigRequest is the HTTP payload used to apply runtime OIDC updates.
type OIDCConfigRequest struct {
	IssuerURL                       string            `json:"issuer_url"`
	ClientID                        string            `json:"client_id"`
	ClaimPolicy                     string            `json:"claim_policy,omitempty"`
	ProviderMode                    oidc.ProviderMode `json:"provider_mode,omitempty"`
	VaultUserInfoFallbackTTLSeconds int64             `json:"vault_userinfo_fallback_ttl_seconds,omitempty"`
	ReplaceExisting                 bool              `json:"replace_existing"`
	DryRun                          bool              `json:"dry_run"`
}

// OIDCProviderStatus describes current runtime OIDC provider state.
type OIDCProviderStatus struct {
	Configured                      bool              `json:"configured"`
	IssuerURL                       string            `json:"issuer_url"`
	ClientID                        string            `json:"client_id"`
	ClaimPolicy                     string            `json:"claim_policy"`
	ProviderMode                    oidc.ProviderMode `json:"provider_mode"`
	VaultUserInfoFallbackTTLSeconds int64             `json:"vault_userinfo_fallback_ttl_seconds,omitempty"`
	LocalUserMintEnabled            bool              `json:"local_user_mint_enabled"`
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

	// RFC 7009: Token revocation store for invalidated JTIs
	revocationStore *RevocationStore

	// Trust roots for inbound mTLS service identity certificates.
	serviceIdentityCAPool      *x509.CertPool
	serviceIdentityPolicyStore *ServiceIdentityPolicyStore
	oidcHTTPClient             *http.Client
}

// IsRevoked implements authn.RevocationChecker for consumers that want to
// enforce this service's process-local revocation store.
func (s *TokenService) IsRevoked(jti string) bool {
	if s == nil || s.revocationStore == nil {
		return false
	}
	return s.revocationStore.IsRevoked(jti)
}

func loadCertPoolFromPEMFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file %q: %w", path, err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("PEM file %q did not contain any valid certificates", path)
	}

	return pool, nil
}

func newOIDCHTTPClient(caPath string) (*http.Client, error) {
	if strings.TrimSpace(caPath) == "" {
		return nil, nil
	}

	caPool, err := loadCertPoolFromPEMFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load upstream OIDC CA bundle: %w", err)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}
	clone := transport.Clone()
	if clone.TLSClientConfig == nil {
		clone.TLSClientConfig = &tls.Config{}
	} else {
		clone.TLSClientConfig = clone.TLSClientConfig.Clone()
	}
	clone.TLSClientConfig.RootCAs = caPool

	return &http.Client{Transport: clone}, nil
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
		Configured:                      strings.TrimSpace(s.Config.OIDCIssuerURL) != "" && strings.TrimSpace(s.Config.OIDCClientID) != "",
		IssuerURL:                       s.Config.OIDCIssuerURL,
		ClientID:                        s.Config.OIDCClientID,
		ClaimPolicy:                     string(s.Config.OIDCClaimPolicy),
		ProviderMode:                    s.Config.OIDCProviderMode,
		VaultUserInfoFallbackTTLSeconds: int64(s.Config.VaultUserInfoFallbackTTL / time.Second),
		LocalUserMintEnabled:            s.Config.EnableLocalUserMint,
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
	claimPolicy := s.Config.OIDCClaimPolicy
	if update.ClaimPolicy != "" {
		parsed, err := ParseOIDCClaimPolicy(update.ClaimPolicy)
		if err != nil {
			return "", s.GetOIDCProviderStatus(), err
		}
		claimPolicy = parsed
	}
	providerMode, err := oidc.ParseProviderMode(string(s.Config.OIDCProviderMode))
	if err != nil {
		return "", s.GetOIDCProviderStatus(), err
	}
	if update.ProviderMode != "" {
		parsed, err := oidc.ParseProviderMode(string(update.ProviderMode))
		if err != nil {
			return "", s.GetOIDCProviderStatus(), err
		}
		providerMode = parsed
	}
	vaultTTL := s.Config.VaultUserInfoFallbackTTL
	if vaultTTL == 0 {
		vaultTTL = oidc.DefaultVaultUserInfoFallbackTTL
	}
	if update.VaultUserInfoFallbackTTLSeconds > 0 {
		vaultTTL = time.Duration(update.VaultUserInfoFallbackTTLSeconds) * time.Second
		if err := oidc.ValidateVaultUserInfoFallbackTTL(vaultTTL); err != nil {
			return "", s.GetOIDCProviderStatus(), err
		}
	}

	secret := strings.TrimSpace(s.Config.OIDCClientSecret)
	if providerMode == oidc.ProviderModeGeneric && secret == "" {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("OIDC client secret is not configured in service environment")
	}

	hasExisting := s.hasConfiguredOIDCProvider()
	if hasExisting && !update.ReplaceExisting {
		return "", s.GetOIDCProviderStatus(), fmt.Errorf("OIDC provider already configured; use --replace-existing to overwrite")
	}

	oidcOptions := []oidc.SimpleProviderOption{}
	if s.oidcHTTPClient != nil {
		oidcOptions = append(oidcOptions, oidc.WithHTTPClient(s.oidcHTTPClient))
	}
	if s.Config.OIDCIntrospectionEndpoint != "" {
		oidcOptions = append(oidcOptions, oidc.WithIntrospectionEndpoint(s.Config.OIDCIntrospectionEndpoint))
	}
	oidcOptions = append(oidcOptions,
		oidc.WithProviderMode(providerMode),
		oidc.WithVaultUserInfoFallbackTTL(vaultTTL),
	)
	provider := oidc.NewSimpleProvider(issuerURL, clientID, secret, oidcOptions...)
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
	s.Config.OIDCClaimPolicy = claimPolicy
	s.Config.OIDCProviderMode = providerMode
	s.Config.VaultUserInfoFallbackTTL = vaultTTL
	s.mu.Unlock()

	if hasExisting {
		return "replaced", s.GetOIDCProviderStatus(), nil
	}
	return "created", s.GetOIDCProviderStatus(), nil
}
