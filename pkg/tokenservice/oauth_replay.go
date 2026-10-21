// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

func (s *TokenService) generateOpaqueToken(bytes int) (string, error) {
	token := make([]byte, bytes)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return hex.EncodeToString(token), nil
}

func (s *TokenService) recordBootstrapReplayAttempt(tokenHash, clientIP string) {
	s.replayLimiter.record(clientIP)
	log.Warn().
		Str("component", "tokenservice").
		Str("token_hash_prefix", tokenHash[:8]).
		Str("client_ip", clientIP).
		Msg("Bootstrap token replay attempt recorded")
	AuditLogBootstrapReplay(tokenHash[:8], clientIP, []time.Time{time.Now()})
}

func (s *TokenService) recordUnknownBootstrapAttempt(clientIP string) {
	s.replayLimiter.record(clientIP)
	AuditLogAuthenticationFailed("", "bootstrap_token_unknown", clientIP)
}

func (s *TokenService) auditRefreshReplay(tokenHash, clientIP string) {
	family, err := s.refreshTokenStore.GetFamilyByTokenHash(tokenHash)
	if err != nil {
		AuditLogAuthenticationFailed("", "refresh_token_not_found", clientIP)
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Msg("Failed to load revoked refresh token family for audit")
		return
	}
	AuditLogRefreshReplayDetected(family.Subject, family.Audience, family.FamilyID, clientIP, family.LastUsedAt)
	AuditLogFamilyRevoked(family.Subject, family.Audience, family.FamilyID, clientIP, family.UsageCount)
}

// handleRefreshTokenGrant processes RFC 6749 refresh token grant requests.
// Refresh tokens are rotated on every use (NIST SP 800-63-4 Section 6.2.2).
func (s *TokenService) handleRefreshTokenGrant(w http.ResponseWriter, _ *http.Request,
	req OAuthTokenRequest, clientIP string) {

	if strings.TrimSpace(req.RefreshToken) == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"Missing or empty refresh_token parameter")
		return
	}

	tokenHash := HashBootstrapToken(req.RefreshToken)
	family, err := s.refreshTokenStore.GetFamilyByTokenHash(tokenHash)
	if err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The provided refresh token is invalid or has expired")
		return
	}
	refreshExpiresIn, err := oauthLifetimeSeconds(time.Until(family.ExpiresAt))
	if err != nil {
		AuditLogAuthenticationFailed(family.Subject, "refresh_token_expired", clientIP)
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The provided refresh token is invalid or has expired")
		return
	}
	newRefreshToken, err := s.generateOpaqueToken(32)
	if err != nil {
		log.Error().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Err(err).
			Msg("Failed to generate refresh token successor")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}
	accessToken, err := generateServiceTokenForOAuth(s, family.Subject, family.Audience, family.Scopes, 3600*time.Second)
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("subject", family.Subject).
			Msg("Failed to generate access token for refresh")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}

	presentedFamily := family
	family, err = s.refreshTokenStore.RotateOrRevoke(tokenHash, HashBootstrapToken(newRefreshToken), time.Now())
	if err != nil {
		if committedWriteWarning(err) && family != nil {
			log.Warn().Err(err).Str("component", "tokenservice").Str("handler", "oauth_token").Msg("Refresh rotation committed with durability warning")
		} else {
			if errors.Is(err, ErrRefreshTokenReplay) {
				AuditLogAuthenticationFailed("", "refresh_token_replay", clientIP)
				s.auditRefreshReplay(tokenHash, clientIP)
			}
			if errors.Is(err, ErrRefreshTokenUnknown) {
				AuditLogAuthenticationFailed("", "refresh_token_not_found", clientIP)
			}
			if errors.Is(err, ErrRefreshTokenRevoked) {
				AuditLogAuthenticationFailed(presentedFamily.Subject, "refresh_token_revoked", clientIP)
			}
			if errors.Is(err, ErrRefreshFamilyExpired) {
				AuditLogAuthenticationFailed(presentedFamily.Subject, "refresh_token_expired", clientIP)
			}
			if errors.Is(err, ErrRefreshTokenReplay) || errors.Is(err, ErrRefreshTokenUnknown) || errors.Is(err, ErrRefreshTokenRevoked) || errors.Is(err, ErrRefreshFamilyExpired) {
				log.Warn().
					Str("component", "tokenservice").
					Str("handler", "oauth_token").
					Str("client_ip", clientIP).
					Msg("Refresh token grant rejected")
				s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
					"The provided refresh token is invalid or has expired")
				return
			}
			log.Error().
				Err(err).
				Str("component", "tokenservice").
				Str("handler", "oauth_token").
				Msg("Failed to rotate refresh token")

			s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
				"An internal server error occurred")
			return
		}
	}

	familyID := family.FamilyID

	// Log successful refresh
	log.Info().
		Str("component", "tokenservice").
		Str("handler", "oauth_token").
		Str("subject", family.Subject).
		Str("audience", family.Audience).
		Str("client_ip", clientIP).
		Str("family_id", familyID).
		Int("usage_count", family.UsageCount).
		Strs("scopes", family.Scopes).
		Msg("Refresh token rotated successfully")

	// Audit log successful refresh token rotation (NIST SP 800-63-4 Section 6.2.2)
	AuditLogRefreshRotated(family.Subject, family.Audience, family.Scopes, clientIP, familyID, family.UsageCount)

	// Write successful response per RFC 6749 Section 5
	s.writeOAuthTokenResponse(w, http.StatusOK, OAuthTokenResponse{
		AccessToken:      accessToken.JWT,
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     newRefreshToken,
		RefreshExpiresIn: refreshExpiresIn,
		Scope:            strings.Join(family.Scopes, " "),
		IssuedTokenType:  AccessTokenTypeRFC8693,
	})
}
