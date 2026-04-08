// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/token"
)

// MintBootstrapToken creates a short-lived bootstrap token intended for one-time
// exchange at /service/token to obtain a standard service token.
func (s *TokenService) MintBootstrapToken(ctx context.Context, serviceID, targetService string, scopes []string, ttl time.Duration) (string, error) {
	if serviceID == "" {
		return "", errors.New("service ID cannot be empty")
	}
	if targetService == "" {
		return "", errors.New("target service cannot be empty")
	}
	if ttl <= 0 {
		return "", errors.New("ttl must be greater than zero")
	}

	now := time.Now()
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   serviceID,
			Audience:  []string{BootstrapAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		Scope:       append([]string(nil), scopes...),
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"bootstrap", "offline"},
		SessionID:   fmt.Sprintf("bootstrap-%s-%d", serviceID, now.UnixNano()),
		SessionExp:  now.Add(ttl).Unix(),
		AuthEvents:  []string{"bootstrap_mint"},
	}

	additionalClaims := map[string]interface{}{
		BootstrapTokenUseField: BootstrapTokenUseClaim,
		BootstrapTargetField:   targetService,
		BootstrapScopesField:   append([]string(nil), scopes...),
		BootstrapOneTimeField:  true,
	}

	tokenValue, err := s.TokenManager.GenerateTokenWithClaims(claims, additionalClaims)
	if err != nil {
		return "", err
	}

	// Audit log bootstrap token creation (admin action, NIST SP 800-63-4 Section 6.2.1)
	AuditLogBootstrapCreated(serviceID, targetService, scopes, ttl, 0, "")

	return tokenValue, nil
}

// MintServiceToken generates a service-to-service token.
func (s *TokenService) MintServiceToken(ctx context.Context, serviceID, targetService string, scopes []string) (string, error) {
	if serviceID == "" {
		return "", errors.New("service ID cannot be empty")
	}
	if targetService == "" {
		return "", errors.New("target service cannot be empty")
	}

	now := time.Now()
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   serviceID,
			Audience:  []string{targetService},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		Scope:       scopes,
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"service", "certificate"},
		SessionID:   fmt.Sprintf("service-%s-%d", serviceID, now.UnixNano()),
		SessionExp:  now.Add(24 * time.Hour).Unix(),
		AuthEvents:  []string{"service_auth"},
	}

	return s.TokenManager.GenerateToken(claims)
}

// MintRefreshToken creates a short-lived one-time refresh token used to obtain
// the next service token from /service/token using grant_type=refresh_token.
func (s *TokenService) MintRefreshToken(ctx context.Context, serviceID, targetService string, scopes []string, ttl time.Duration) (string, error) {
	if serviceID == "" {
		return "", errors.New("service ID cannot be empty")
	}
	if targetService == "" {
		return "", errors.New("target service cannot be empty")
	}
	if ttl <= 0 {
		return "", errors.New("ttl must be greater than zero")
	}

	now := time.Now()
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   serviceID,
			Audience:  []string{RefreshAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		Scope:       append([]string(nil), scopes...),
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"refresh", "service"},
		SessionID:   fmt.Sprintf("refresh-%s-%d", serviceID, now.UnixNano()),
		SessionExp:  now.Add(ttl).Unix(),
		AuthEvents:  []string{"refresh_mint"},
	}

	additionalClaims := map[string]interface{}{
		RefreshTokenUseField: RefreshTokenUseClaim,
		RefreshTargetField:   targetService,
		RefreshScopesField:   append([]string(nil), scopes...),
		RefreshOneTimeField:  true,
	}

	return s.TokenManager.GenerateTokenWithClaims(claims, additionalClaims)
}

// ValidateToken validates a token and returns its claims.
func (s *TokenService) ValidateToken(ctx context.Context, tokenString string) (*token.TSClaims, error) {
	claims, _, err := s.TokenManager.ParseToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	return claims, nil
}

// UpdateGroupScopes updates the group-to-scope mapping.
func (s *TokenService) UpdateGroupScopes(groupScopes map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GroupScopes = groupScopes
}

// GenerateServiceToken generates a service-to-service access token for RFC 8693 token exchange.
// Unlike MintServiceToken which is used internally, this creates a token from an already-authorized
// bootstrap token's server-side policy.
// See: RFC 8693 Section 2.2.1 (Access Token Response)
func (s *TokenService) GenerateServiceToken(subject, audience string, scopes []string, ttl time.Duration) (string, error) {
	if subject == "" {
		return "", errors.New("subject cannot be empty")
	}
	if audience == "" {
		return "", errors.New("audience cannot be empty")
	}
	if ttl <= 0 {
		return "", errors.New("ttl must be greater than zero")
	}

	now := time.Now()
	claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Issuer,
			Subject:   subject,
			Audience:  []string{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        fmt.Sprintf("st-%d", now.UnixNano()), // Token ID for audit
		},
		ClusterID:   s.ClusterID,
		OpenCHAMIID: s.OpenCHAMIID,
		Scope:       append([]string(nil), scopes...), // Immutable server-determined scopes
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"bootstrap_exchange"},
		SessionID:   fmt.Sprintf("bootstrap-exchange-%s-%d", subject, now.UnixNano()),
		SessionExp:  now.Add(ttl).Unix(),
		AuthEvents:  []string{"bootstrap_token_exchange"},
	}

	return s.TokenManager.GenerateToken(claims)
}

// GenerateRefreshToken generates a refresh token and creates a token family for replay detection.
// Per RFC 6749 Section 6, refresh tokens are used to obtain new access tokens without re-authentication.
// Per NIST SP 800-63-4 Section 6.2.3, we track token families for replay detection.
// See: RFC 6749 Section 6, NIST SP 800-63-4 Section 6.2.3
func (s *TokenService) GenerateRefreshToken(subject, audience string, scopes []string, maxTTL time.Duration) (string, string, error) {
	if subject == "" {
		return "", "", errors.New("subject cannot be empty")
	}
	if audience == "" {
		return "", "", errors.New("audience cannot be empty")
	}
	if maxTTL <= 0 {
		return "", "", errors.New("max_ttl must be greater than zero")
	}

	now := time.Now()

	// Generate new refresh token (opaque, 256 bits)
	refreshToken, err := s.generateOpaqueToken(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create token family for rotation tracking
	familyID := fmt.Sprintf("family-%d", now.UnixNano())
	family := &RefreshTokenFamily{
		FamilyID:         familyID,
		CurrentTokenHash: HashBootstrapToken(refreshToken),
		Subject:          subject,
		Audience:         audience,
		Scopes:           append([]string(nil), scopes...), // Immutable
		IssuedAt:         now,
		ExpiresAt:        now.Add(maxTTL),
		LastUsedAt:       now,
		UsageCount:       0, // First generation, not yet used
	}

	// Store family for replay detection
	if err := s.refreshTokenStore.SaveFamily(family); err != nil {
		return "", "", fmt.Errorf("failed to save refresh token family: %w", err)
	}

	// Opaque refresh tokens are stored server-side indexed by family ID.
	// The family's CurrentTokenHash field allows lookup by token hash.
	// See: RFC 6749 Section 6, NIST SP 800-63-4 Section 6.2.3

	return refreshToken, familyID, nil
}
