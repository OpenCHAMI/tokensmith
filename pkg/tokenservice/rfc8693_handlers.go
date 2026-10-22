// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
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

	clientIP := requestClientIP(r)

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
func (s *TokenService) handleBootstrapTokenExchange(w http.ResponseWriter, _ *http.Request,
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
	policy, err := s.bootstrapTokenStore.GetPolicy(tokenHash)
	if err != nil {
		s.recordUnknownBootstrapAttempt(clientIP)
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The provided token is invalid or has already been used")
		return
	}
	refreshExpiresIn, err := oauthLifetimeSeconds(policy.RefreshTTL)
	if err != nil {
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "An internal server error occurred")
		return
	}

	policy, err = s.bootstrapTokenStore.ConsumePolicy(tokenHash, clientIP, time.Now())
	if err != nil {
		if committedWriteWarning(err) && policy != nil {
			log.Warn().Err(err).Str("component", "tokenservice").Str("handler", "oauth_token").Msg("Bootstrap consumption committed with durability warning")
		} else {
			if errors.Is(err, ErrBootstrapTokenConsumed) {
				s.recordBootstrapReplayAttempt(tokenHash, clientIP)
				AuditLogAuthenticationFailed(policy.Subject, "bootstrap_token_consumed", clientIP)
			}
			if errors.Is(err, ErrBootstrapTokenExpired) {
				AuditLogAuthenticationFailed(policy.Subject, "bootstrap_token_expired", clientIP)
			}
			log.Warn().
				Str("component", "tokenservice").
				Str("handler", "oauth_token").
				Str("client_ip", clientIP).
				Str("token_hash_prefix", tokenHash[:8]).
				Msg("Bootstrap token exchange rejected")

			if !errors.Is(err, ErrBootstrapTokenExpired) && !errors.Is(err, ErrBootstrapTokenConsumed) {
				s.recordBootstrapReplayAttempt(tokenHash, clientIP)
			}
			s.writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
				"The provided token is invalid or has already been used")
			return
		}
	}

	// Generate service token (access token) with server-determined scopes
	accessToken, err := generateServiceTokenForOAuth(s, policy.Subject, policy.Audience, policy.Scopes, 3600*time.Second)
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
	policy.IssuedAccessTokenID = accessToken.JTI
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
		Str("access_token_id", accessToken.JTI).
		Strs("scopes", policy.Scopes).
		Msg("Bootstrap token successfully exchanged for service token")

	// Audit log successful bootstrap exchange (RFC 8693 Section 3.2)
	AuditLogBootstrapExchanged(policy.Subject, policy.Audience, policy.Scopes, clientIP, accessToken.JTI, familyID, tokenHash[:8])

	// Write successful response per RFC 8693 Section 2.2
	s.writeOAuthTokenResponse(w, http.StatusOK, OAuthTokenResponse{
		AccessToken:      accessToken.JWT,
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     refreshToken,
		RefreshExpiresIn: refreshExpiresIn,
		Scope:            strings.Join(policy.Scopes, " "),
		IssuedTokenType:  AccessTokenTypeRFC8693,
	})
}
