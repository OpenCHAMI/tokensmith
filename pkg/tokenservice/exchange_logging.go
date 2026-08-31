// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"net"
	"net/http"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog/log"
)

const exchangeFailureEvent = "token_exchange_failed"

func logExchangeFailure(r *http.Request, claimPolicy OIDCClaimPolicy, statusCode int, category string, scopeCount int, hasTargetService bool, err error) {
	event := log.Warn().
		Str("component", "tokenservice").
		Str("handler", "oauth_exchange").
		Str("audit_event", exchangeFailureEvent).
		Str("client_ip", exchangeClientIP(r)).
		Str("claim_policy", string(claimPolicy)).
		Str("failure_category", category).
		Int("status_code", statusCode).
		Int("requested_scope_count", scopeCount).
		Bool("has_target_service", hasTargetService)

	if requestID := r.Header.Get("X-Request-Id"); requestID != "" {
		event = event.Str("request_id", requestID)
	}
	if providerErr := exchangeProviderError(err); providerErr != nil {
		event = event.Str("provider_operation", providerErr.Operation)
		if providerErr.StatusCode != 0 {
			event = event.Int("upstream_status_code", providerErr.StatusCode)
		}
		if providerErr.Cause != nil && errors.Is(providerErr, oidc.ErrProviderMetadata) {
			event = event.Str("provider_detail", providerErr.Cause.Error())
		}
	}
	if missingClaims := exchangeMissingClaimNames(err); len(missingClaims) > 0 {
		event = event.Strs("missing_claims", missingClaims)
	}
	if errors.Is(err, ErrExchangeGeneratedClaimValidation) {
		event = event.Str("failure_stage", "generate_token")
	}

	event.Msg(exchangeFailureEvent)
}

func exchangeFailureCategory(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, ErrExchangeMissingClaims):
		return "missing_claim"
	case errors.Is(err, ErrExchangeInvalidClaim):
		return "invalid_claim"
	case errors.Is(err, ErrExchangeGeneratedClaimValidation):
		return "generated_claim_validation"
	case errors.Is(err, oidc.ErrUpstreamUnavailable):
		return "upstream_unavailable"
	case errors.Is(err, oidc.ErrUpstreamRejected):
		return "upstream_rejected"
	case errors.Is(err, oidc.ErrInvalidResponse):
		return "invalid_response"
	case errors.Is(err, oidc.ErrInvalidToken):
		return "invalid_token"
	case errors.Is(err, oidc.ErrProviderMetadata):
		return "provider_metadata"
	default:
		return "exchange_failed"
	}
}

func exchangeMissingClaimNames(err error) []string {
	var claimsErr *ExchangeClaimsError
	if !errors.As(err, &claimsErr) || len(claimsErr.Claims) == 0 {
		return nil
	}
	return append([]string(nil), claimsErr.Claims...)
}

func exchangeProviderError(err error) *oidc.ProviderError {
	var providerErr *oidc.ProviderError
	if !errors.As(err, &providerErr) {
		return nil
	}
	return providerErr
}

func exchangeClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
