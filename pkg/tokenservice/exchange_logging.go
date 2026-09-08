// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"net"
	"net/http"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/rs/zerolog/log"
)

type exchangeLogContext struct {
	Request         *http.Request
	ClaimPolicy     OIDCClaimPolicy
	StatusCode      int
	RequestedScopes []string
	TargetService   string
	Err             error
	Claims          *token.TSClaims
}

func logExchangeFailure(ctx exchangeLogContext) {
	event := log.Warn().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldHandler), string(LogHandlerOAuthExchange)).
		Str(string(LogFieldAuditEvent), string(LogEventTokenExchangeFailed)).
		Str(string(LogFieldClientIP), exchangeClientIP(ctx.Request)).
		Str(string(LogFieldOIDCClaimPolicy), string(ctx.ClaimPolicy)).
		Str(string(LogFieldFailureCategory), exchangeFailureCategory(ctx.Err)).
		Int("status_code", ctx.StatusCode).
		Int(string(LogFieldRequestedScopeCount), len(ctx.RequestedScopes)).
		Bool(string(LogFieldHasTargetService), ctx.TargetService != "")

	if requestID := ctx.Request.Header.Get("X-Request-Id"); requestID != "" {
		event = event.Str(string(LogFieldRequestID), requestID)
	}
	if len(ctx.RequestedScopes) > 0 {
		event = event.Strs(string(LogFieldRequestedScopes), ctx.RequestedScopes)
	}
	if ctx.TargetService != "" {
		event = event.Str(string(LogFieldTargetService), ctx.TargetService)
	}
	if providerErr := exchangeProviderError(ctx.Err); providerErr != nil {
		event = event.Str(string(LogFieldProviderOp), providerErr.Operation)
		if providerErr.StatusCode != 0 {
			event = event.Int(string(LogFieldUpstreamStatus), providerErr.StatusCode)
		}
		if providerErr.Cause != nil && errors.Is(providerErr, oidc.ErrProviderMetadata) {
			event = event.Str("provider_detail", providerErr.Cause.Error())
		}
	}
	if missingClaims := exchangeMissingClaimNames(ctx.Err); len(missingClaims) > 0 {
		event = event.Strs("missing_claims", missingClaims)
	}
	if rejectedScope, derivedScopes := exchangeRejectedScope(ctx.Err); rejectedScope != "" {
		event = event.Str(string(LogFieldRejectedScope), rejectedScope)
		event = event.Strs(string(LogFieldDerivedScopes), derivedScopes)
	}
	if errors.Is(ctx.Err, ErrExchangeGeneratedClaimValidation) {
		event = event.Str(string(LogFieldFailureStage), "generate_token")
	}

	event.Msg(string(LogEventTokenExchangeFailed))
}

func logExchangeSuccess(ctx exchangeLogContext) {
	event := log.Info().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldHandler), string(LogHandlerOAuthExchange)).
		Str(string(LogFieldAuditEvent), string(LogEventTokenExchangeSucceeded)).
		Str(string(LogFieldClientIP), exchangeClientIP(ctx.Request)).
		Str(string(LogFieldOIDCClaimPolicy), string(ctx.ClaimPolicy)).
		Int(string(LogFieldRequestedScopeCount), len(ctx.RequestedScopes)).
		Bool(string(LogFieldHasTargetService), ctx.TargetService != "")

	if requestID := ctx.Request.Header.Get("X-Request-Id"); requestID != "" {
		event = event.Str(string(LogFieldRequestID), requestID)
	}
	if len(ctx.RequestedScopes) > 0 {
		event = event.Strs(string(LogFieldRequestedScopes), ctx.RequestedScopes)
	}
	if ctx.TargetService != "" {
		event = event.Str(string(LogFieldTargetService), ctx.TargetService)
	}
	if ctx.Claims != nil {
		event = event.Str(string(LogFieldSubject), ctx.Claims.Subject)
		event = event.Strs(string(LogFieldAudience), ctx.Claims.Audience)
		event = event.Strs(string(LogFieldDerivedScopes), ctx.Claims.Scope)
		if ctx.Claims.ExpiresAt != nil && ctx.Claims.IssuedAt != nil {
			event = event.Int64(string(LogFieldGeneratedTokenLifetimeSeconds), int64(ctx.Claims.ExpiresAt.Sub(ctx.Claims.IssuedAt.Time).Seconds()))
		}
	}

	event.Msg(string(LogEventTokenExchangeSucceeded))
}

func exchangeFailureCategory(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, ErrExchangeMissingClaims):
		return "missing_claim"
	case errors.Is(err, ErrExchangeInactiveToken):
		return string(LogFailureInactiveToken)
	case errors.Is(err, ErrExchangeScopeNotGranted):
		return string(LogFailureScopeNotGranted)
	case errors.Is(err, ErrExchangeInvalidClaim):
		return string(LogFailureInvalidClaim)
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

func exchangeRejectedScope(err error) (string, []string) {
	var claimsErr *ExchangeClaimsError
	if !errors.As(err, &claimsErr) || !errors.Is(claimsErr.Kind, ErrExchangeScopeNotGranted) || claimsErr.RejectedScope == "" {
		return "", nil
	}
	return claimsErr.RejectedScope, append([]string(nil), claimsErr.Allowed...)
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
