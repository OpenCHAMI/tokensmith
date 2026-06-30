// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import "time"

// bootstrapTokenPolicyStorage is the internal disk storage format for BootstrapTokenPolicy.
// This includes the TokenHash field which is excluded from the public API JSON representation.
type bootstrapTokenPolicyStorage struct {
	ID                   string        `json:"id"`
	Subject              string        `json:"subject"`
	Audience             string        `json:"audience"`
	Scopes               []string      `json:"scopes"`
	TTL                  time.Duration `json:"ttl"`
	RefreshTTL           time.Duration `json:"refresh_ttl"`
	TokenHash            string        `json:"token_hash"` // Included for disk storage
	CreatedAt            time.Time     `json:"created_at"`
	ExpiresAt            time.Time     `json:"expires_at"`
	ConsumedAt           *time.Time    `json:"consumed_at,omitempty"`
	ConsumedByIP         string        `json:"consumed_by_ip,omitempty"`
	ReplayAttempts       []time.Time   `json:"replay_attempts,omitempty"`
	BindingIdentifier    string        `json:"binding_identifier,omitempty"`
	IssuedAccessTokenID  string        `json:"issued_access_token_id,omitempty"`
	IssuedRefreshTokenID string        `json:"issued_refresh_token_id,omitempty"`
}

// toStorage converts BootstrapTokenPolicy to storage format.
func (p *BootstrapTokenPolicy) toStorage() *bootstrapTokenPolicyStorage {
	return &bootstrapTokenPolicyStorage{
		ID:                   p.ID,
		Subject:              p.Subject,
		Audience:             p.Audience,
		Scopes:               p.Scopes,
		TTL:                  p.TTL,
		RefreshTTL:           p.RefreshTTL,
		TokenHash:            p.TokenHash,
		CreatedAt:            p.CreatedAt,
		ExpiresAt:            p.ExpiresAt,
		ConsumedAt:           p.ConsumedAt,
		ConsumedByIP:         p.ConsumedByIP,
		ReplayAttempts:       p.ReplayAttempts,
		BindingIdentifier:    p.BindingIdentifier,
		IssuedAccessTokenID:  p.IssuedAccessTokenID,
		IssuedRefreshTokenID: p.IssuedRefreshTokenID,
	}
}

// fromStorage converts storage format to BootstrapTokenPolicy.
func (s *bootstrapTokenPolicyStorage) fromStorage() *BootstrapTokenPolicy {
	return &BootstrapTokenPolicy{
		ID:                   s.ID,
		Subject:              s.Subject,
		Audience:             s.Audience,
		Scopes:               s.Scopes,
		TTL:                  s.TTL,
		RefreshTTL:           s.RefreshTTL,
		TokenHash:            s.TokenHash,
		CreatedAt:            s.CreatedAt,
		ExpiresAt:            s.ExpiresAt,
		ConsumedAt:           s.ConsumedAt,
		ConsumedByIP:         s.ConsumedByIP,
		ReplayAttempts:       s.ReplayAttempts,
		BindingIdentifier:    s.BindingIdentifier,
		IssuedAccessTokenID:  s.IssuedAccessTokenID,
		IssuedRefreshTokenID: s.IssuedRefreshTokenID,
	}
}

// refreshTokenFamilyStorage is the internal disk storage format for RefreshTokenFamily.
// This includes the CurrentTokenHash field which is excluded from the public API JSON representation.
type refreshTokenFamilyStorage struct {
	FamilyID          string     `json:"family_id"`
	CurrentTokenHash  string     `json:"current_token_hash"` // Included for disk storage
	Subject           string     `json:"subject"`
	Audience          string     `json:"audience"`
	Scopes            []string   `json:"scopes"`
	IssuedAt          time.Time  `json:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	LastUsedAt        time.Time  `json:"last_used_at"`
	UsageCount        int        `json:"usage_count"`
	ReplayDetectedAt  *time.Time `json:"replay_detected_at,omitempty"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	BindingIdentifier string     `json:"binding_identifier,omitempty"`
}

// toStorage converts RefreshTokenFamily to storage format.
func (f *RefreshTokenFamily) toStorage() *refreshTokenFamilyStorage {
	return &refreshTokenFamilyStorage{
		FamilyID:          f.FamilyID,
		CurrentTokenHash:  f.CurrentTokenHash,
		Subject:           f.Subject,
		Audience:          f.Audience,
		Scopes:            f.Scopes,
		IssuedAt:          f.IssuedAt,
		ExpiresAt:         f.ExpiresAt,
		LastUsedAt:        f.LastUsedAt,
		UsageCount:        f.UsageCount,
		ReplayDetectedAt:  f.ReplayDetectedAt,
		RevokedAt:         f.RevokedAt,
		BindingIdentifier: f.BindingIdentifier,
	}
}

// fromStorage converts storage format to RefreshTokenFamily.
func (s *refreshTokenFamilyStorage) fromStorage() *RefreshTokenFamily {
	return &RefreshTokenFamily{
		FamilyID:          s.FamilyID,
		CurrentTokenHash:  s.CurrentTokenHash,
		Subject:           s.Subject,
		Audience:          s.Audience,
		Scopes:            s.Scopes,
		IssuedAt:          s.IssuedAt,
		ExpiresAt:         s.ExpiresAt,
		LastUsedAt:        s.LastUsedAt,
		UsageCount:        s.UsageCount,
		ReplayDetectedAt:  s.ReplayDetectedAt,
		RevokedAt:         s.RevokedAt,
		BindingIdentifier: s.BindingIdentifier,
	}
}
