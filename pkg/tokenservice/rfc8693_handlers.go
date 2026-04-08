// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// OAuthTokenHandler implements the RFC 8693 token endpoint.
// See: https://datatracker.ietf.org/doc/html/rfc8693#section-2
//
// Supported grant types:
// - urn:ietf:params:oauth:grant-type:token-exchange (bootstrap exchange)
// - refresh_token (RFC 6749 Section 6)
func (s *TokenService) OAuthTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Parse request body per RFC 8693 Section 2.1
	var req OAuthTokenRequest
	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	req.GrantType = r.FormValue("grant_type")
	req.SubjectToken = r.FormValue("subject_token")
	req.SubjectTokenType = r.FormValue("subject_token_type")
	req.RefreshToken = r.FormValue("refresh_token")

	if strings.TrimSpace(req.GrantType) == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing grant_type parameter")
		return
	}

	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	}

	// Route to appropriate grant handler per RFC 8693 Section 2
	switch req.GrantType {
	case GrantTypeTokenExchange:
		s.handleBootstrapTokenExchange(w, r, req, clientIP)
	case GrantTypeRefreshTokenRFC8693:
		s.handleRefreshTokenGrant(w, r, req, clientIP)
	default:
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("Grant type '%s' is not supported", req.GrantType))
	}
}

// handleBootstrapTokenExchange processes RFC 8693 token exchange requests.
// Bootstrap tokens are opaque, one-time-use credentials that map to server-side policies.
func (s *TokenService) handleBootstrapTokenExchange(w http.ResponseWriter, r *http.Request,
	req OAuthTokenRequest, clientIP string) {

	// Rate limit check: reject IPs that have exceeded the failed-attempt threshold.
	// Per NIST SP 800-63-4 Section 5.2.2 (throttling).
	if s.replayLimiter.isBlocked(clientIP) {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Int("max_attempts", replayMaxAttempts).
			Dur("window", replayWindowDuration).
			Msg("Bootstrap exchange rate limited (too many failed attempts)")

		s.writeOAuthError(w, http.StatusTooManyRequests, "too_many_requests",
			"Too many failed token exchange attempts from this address")
		return
	}

	// Validate required parameters per RFC 8693 Section 2.1
	if req.SubjectTokenType != BootstrapTokenTypeRFC8693 {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("expected_token_type", BootstrapTokenTypeRFC8693).
			Str("received_token_type", req.SubjectTokenType).
			Msg("Invalid subject_token_type for bootstrap exchange")

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"Invalid subject_token_type parameter")
		return
	}

	if strings.TrimSpace(req.SubjectToken) == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"Missing or empty subject_token parameter")
		return
	}

	// Hash the bootstrap token for lookup
	tokenHash := HashBootstrapToken(req.SubjectToken)

	// Retrieve bootstrap policy (server-side only)
	policy, err := s.bootstrapTokenStore.GetPolicy(tokenHash)
	if err != nil {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("token_hash_prefix", tokenHash[:8]).
			Msg("Bootstrap token not found")

		s.recordBootstrapReplayAttempt(tokenHash, clientIP)
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided token is invalid or has already been used")
		return
	}

	// Validate bootstrap token per RFC 8693 Section 3 and NIST SP 800-63
	if policy.IsExpired() {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("subject", policy.Subject).
			Str("token_hash_prefix", tokenHash[:8]).
			Time("expired_at", policy.ExpiresAt).
			Msg("Bootstrap token expired")

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided token is invalid or has already been used")
		AuditLogAuthenticationFailed(policy.Subject, "bootstrap_token_expired", clientIP)
		return
	}

	if policy.IsConsumed() {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("subject", policy.Subject).
			Str("token_hash_prefix", tokenHash[:8]).
			Time("consumed_at", *policy.ConsumedAt).
			Str("consumed_by_ip", policy.ConsumedByIP).
			Msg("Bootstrap token already consumed (replay attempt)")

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided token is invalid or has already been used")
		return
	}

	// Atomically mark bootstrap token as consumed
	now := time.Now()
	policy.ConsumedAt = &now
	policy.ConsumedByIP = clientIP

	if err := s.bootstrapTokenStore.UpdatePolicy(policy); err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("subject", policy.Subject).
			Msg("Failed to mark bootstrap token as consumed")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}

	// Generate service token (access token) with server-determined scopes
	accessToken, err := s.GenerateServiceToken(policy.Subject, policy.Audience, policy.Scopes, 3600*time.Second)
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("subject", policy.Subject).
			Msg("Failed to generate service token")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}

	// Generate refresh token and create token family
	refreshToken, familyID, err := s.GenerateRefreshToken(policy.Subject, policy.Audience, policy.Scopes, policy.RefreshTTL)
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("subject", policy.Subject).
			Msg("Failed to generate refresh token")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}

	// Record token IDs in bootstrap policy for audit
	policy.IssuedAccessTokenID = accessToken
	policy.IssuedRefreshTokenID = familyID
	if err := s.bootstrapTokenStore.UpdatePolicy(policy); err != nil {
		log.Warn().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("subject", policy.Subject).
			Str("token_hash_prefix", tokenHash[:8]).
			Msg("Failed to persist issued token IDs in bootstrap policy")
	}

	// Log successful bootstrap exchange
	log.Info().
		Str("component", "tokenservice").
		Str("handler", "oauth_token").
		Str("subject", policy.Subject).
		Str("audience", policy.Audience).
		Str("client_ip", clientIP).
		Str("token_hash_prefix", tokenHash[:8]).
		Str("refresh_family_id", familyID).
		Strs("scopes", policy.Scopes).
		Msg("Bootstrap token successfully exchanged for service token")

	// Audit log successful bootstrap exchange (RFC 8693 Section 3.2)
	AuditLogBootstrapExchanged(policy.Subject, policy.Audience, policy.Scopes, clientIP, accessToken, familyID, tokenHash[:8])

	// Write successful response per RFC 8693 Section 2.2
	s.writeOAuthTokenResponse(w, http.StatusOK, OAuthTokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: int(policy.RefreshTTL.Seconds()),
		Scope:            strings.Join(policy.Scopes, " "),
		IssuedTokenType:  AccessTokenTypeRFC8693,
	})
}

// handleRefreshTokenGrant processes RFC 6749 refresh token grant requests.
// Refresh tokens are rotated on every use (NIST SP 800-63-4 Section 6.2.2).
func (s *TokenService) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request,
	req OAuthTokenRequest, clientIP string) {

	if strings.TrimSpace(req.RefreshToken) == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"Missing or empty refresh_token parameter")
		return
	}

	// Lookup token family by opaque token hash (per NIST SP 800-63-4 Section 6.2.3)
	tokenHash := HashBootstrapToken(req.RefreshToken)
	family, err := s.refreshTokenStore.GetFamilyByTokenHash(tokenHash)
	if err != nil {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Err(err).
			Msg("Refresh token family not found by hash")

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided refresh token is invalid or has expired")
		AuditLogAuthenticationFailed("", "refresh_token_not_found", clientIP)
		return
	}
	familyID := family.FamilyID

	// If the hash matched a revoked family, that means the old token was replayed
	// after rotation. Check revocation before expiry to give the right error message.
	if family.IsRevoked() {
		log.Error().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("family_id", familyID).
			Str("subject", family.Subject).
			Time("revoked_at", *family.RevokedAt).
			Msg("Refresh token family is revoked (replay detected via hash lookup)")

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided refresh token is invalid or has expired")
		return
	}

	// Check if family is expired (RFC 6749 Section 6)
	if family.IsExpired() {
		log.Warn().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("family_id", familyID).
			Str("subject", family.Subject).
			Time("expired_at", family.ExpiresAt).
			Msg("Refresh token family expired")

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided refresh token is invalid or has expired")
		return
	}

	// Validate refresh token hash (verify it matches current token).
	// Since we looked up the family by hash, a mismatch here means the family's
	// CurrentTokenHash was updated by a concurrent rotation. Treat as replay.
	if tokenHash != family.CurrentTokenHash {
		// Potentially a replay attempt from a rotated token
		log.Error().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("client_ip", clientIP).
			Str("family_id", familyID).
			Str("subject", family.Subject).
			Msg("Refresh token hash mismatch - replay attempt detected")

		// Revoke entire family (NIST SP 800-63-4 Section 6.2.3)
		now := time.Now()
		family.RevokedAt = &now
		if err := s.refreshTokenStore.UpdateFamily(family); err != nil {
			log.Error().
				Err(err).
				Str("component", "tokenservice").
				Str("handler", "oauth_token").
				Str("family_id", familyID).
				Str("subject", family.Subject).
				Msg("Failed to persist refresh token family revocation")

			s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
				"An internal server error occurred")
			return
		}

		log.Error().
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Str("family_id", familyID).
			Str("subject", family.Subject).
			Msg("Refresh token family revoked due to replay attempt")

		// Audit log replay detection and family revocation (NIST SP 800-63-4 Section 6.2.3)
		AuditLogRefreshReplayDetected(family.Subject, family.Audience, familyID, clientIP, family.LastUsedAt)
		AuditLogFamilyRevoked(family.Subject, family.Audience, familyID, clientIP, family.UsageCount)

		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"The provided refresh token is invalid or has expired")
		return
	}

	// Generate new access token with same scopes (immutable, RFC 6749 Section 6)
	accessToken, err := s.GenerateServiceToken(family.Subject, family.Audience, family.Scopes, 3600*time.Second)
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

	// Generate new refresh token (rotation, NIST SP 800-63-4 Section 6.2.2)
	newRefreshToken, err := s.generateOpaqueToken(32) // 256 bits
	if err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Msg("Failed to generate opaque refresh token")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}

	// Update token family with new token and increment usage
	family.CurrentTokenHash = HashBootstrapToken(newRefreshToken)
	family.LastUsedAt = time.Now()
	family.UsageCount++

	if err := s.refreshTokenStore.UpdateFamily(family); err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("family_id", familyID).
			Msg("Failed to update refresh token family")

		s.writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"An internal server error occurred")
		return
	}

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
	refreshExpiresIn := int(time.Until(family.ExpiresAt).Seconds())
	if refreshExpiresIn < 0 {
		refreshExpiresIn = 0
	}
	s.writeOAuthTokenResponse(w, http.StatusOK, OAuthTokenResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     newRefreshToken,
		RefreshExpiresIn: refreshExpiresIn,
		Scope:            strings.Join(family.Scopes, " "),
		IssuedTokenType:  AccessTokenTypeRFC8693,
	})
}

// writeOAuthTokenResponse writes a successful token response.
// See: RFC 8693 Section 2.2, RFC 6749 Section 5.1
func (s *TokenService) writeOAuthTokenResponse(w http.ResponseWriter, statusCode int, resp OAuthTokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Msg("Failed to write OAuth token response")
	}
}

// writeOAuthError writes an error response per RFC 6749 Section 5.2.
// See: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
func (s *TokenService) writeOAuthError(w http.ResponseWriter, statusCode int, errCode, errDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(OAuthErrorResponse{
		Error:            errCode,
		ErrorDescription: errDescription,
	}); err != nil {
		log.Error().
			Err(err).
			Str("component", "tokenservice").
			Str("handler", "oauth_token").
			Msg("Failed to write OAuth error response")
	}
}

// generateOpaqueToken generates a cryptographically secure opaque token.
// Per NIST SP 800-63-3/4 Section 5.1.4.2, tokens must be generated with sufficient entropy.
func (s *TokenService) generateOpaqueToken(bytes int) (string, error) {
	token := make([]byte, bytes)
	if _, err := rand.Read(token); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(token), nil
}

// recordBootstrapReplayAttempt records failed bootstrap token exchange attempts
// for audit logging and rate limiting. It implements NIST SP 800-63-4
// Section 5.2.2 throttling by tracking per-IP attempt counts.
func (s *TokenService) recordBootstrapReplayAttempt(tokenHash, clientIP string) {
	s.replayLimiter.record(clientIP)

	log.Warn().
		Str("component", "tokenservice").
		Str("token_hash_prefix", tokenHash[:8]).
		Str("client_ip", clientIP).
		Msg("Bootstrap token replay attempt recorded")

	// Audit log bootstrap token replay attempt (NIST SP 800-63-4 Section 6.2.3)
	AuditLogBootstrapReplay(tokenHash[:8], clientIP, []time.Time{time.Now()})
}
