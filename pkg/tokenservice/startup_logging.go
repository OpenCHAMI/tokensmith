// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strings"

	"github.com/openchami/tokensmith/pkg/oidc"
	"github.com/rs/zerolog/log"
)

func (s *TokenService) logStartupSummary(addr string, tlsEnabled bool) {
	log.Info().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldEvent), string(LogEventTokenSmithStarted)).
		Str(string(LogFieldHandler), string(LogHandlerStartup)).
		Str(string(LogFieldIssuer), s.Config.Issuer).
		Str(string(LogFieldClusterID), s.Config.ClusterID).
		Str(string(LogFieldOpenCHAMIID), s.Config.OpenCHAMIID).
		Str(string(LogFieldOIDCIssuer), s.Config.OIDCIssuerURL).
		Str(string(LogFieldOIDCClientID), s.Config.OIDCClientID).
		Str(string(LogFieldOIDCClaimPolicy), string(s.Config.OIDCClaimPolicy)).
		Bool(string(LogFieldOIDCCAConfigured), strings.TrimSpace(s.Config.OIDCCAPath) != "").
		Int64(string(LogFieldMaxExchangeSessionLifetimeSeconds), int64(s.Config.MaxExchangeSessionLifetime.Seconds())).
		Str(string(LogFieldBootstrapStorePath), s.Config.RFC8693BootstrapStorePath).
		Str(string(LogFieldRefreshStorePath), s.Config.RFC8693RefreshStorePath).
		Bool(string(LogFieldTLSEnabled), tlsEnabled).
		Bool(string(LogFieldServiceIdentityMTLSEnabled), s.serviceIdentityCAPool != nil).
		Bool(string(LogFieldLocalUserMintEnabled), s.Config.EnableLocalUserMint).
		Str(string(LogFieldListenAddr), addr).
		Msg(string(LogEventTokenSmithStarted))
}

func (s *TokenService) logOIDCProviderValidation(ctx context.Context) {
	if !s.hasConfiguredOIDCProvider() {
		return
	}

	provider := s.currentOIDCProvider()
	if provider == nil {
		s.logOIDCProviderValidationFailure(nil, LogFailureClientConfigMissing, "get provider metadata")
		return
	}

	log.Info().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldEvent), string(LogEventOIDCProviderValidationStarted)).
		Str(string(LogFieldHandler), string(LogHandlerStartup)).
		Str(string(LogFieldOIDCIssuer), s.Config.OIDCIssuerURL).
		Str(string(LogFieldOIDCClientID), s.Config.OIDCClientID).
		Str(string(LogFieldOIDCClaimPolicy), string(s.Config.OIDCClaimPolicy)).
		Bool(string(LogFieldOIDCCAConfigured), strings.TrimSpace(s.Config.OIDCCAPath) != "").
		Msg(string(LogEventOIDCProviderValidationStarted))

	metadata, err := provider.GetProviderMetadata(ctx)
	if err != nil {
		s.logOIDCProviderValidationFailure(err, classifyProviderValidationFailure(err, LogFailureProviderMetadata), providerOperation(err, "get provider metadata"))
		return
	}
	jwks, err := provider.GetJWKS(ctx)
	if err != nil {
		s.logOIDCProviderValidationFailure(err, classifyProviderValidationFailure(err, LogFailureJWKSUnavailable), providerOperation(err, "get JWKS"))
		return
	}
	if !validJWKS(jwks) {
		s.logOIDCProviderValidationFailure(nil, LogFailureJWKSInvalid, "validate JWKS")
		return
	}

	log.Info().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldEvent), string(LogEventOIDCProviderValidationOK)).
		Str(string(LogFieldHandler), string(LogHandlerStartup)).
		Str(string(LogFieldOIDCIssuer), s.Config.OIDCIssuerURL).
		Str(string(LogFieldOIDCClientID), s.Config.OIDCClientID).
		Str(string(LogFieldOIDCClaimPolicy), string(s.Config.OIDCClaimPolicy)).
		Str(string(LogFieldMetadataIssuer), metadata.Issuer).
		Str(string(LogFieldIntrospectionEndpointSource), introspectionEndpointSource(metadata)).
		Int(string(LogFieldJWKSKeyCount), jwksKeyCount(jwks)).
		Msg(string(LogEventOIDCProviderValidationOK))
}

func (s *TokenService) logOIDCProviderValidationFailure(err error, category LogFailureCategory, operation string) {
	log.Warn().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldEvent), string(LogEventOIDCProviderValidationFailed)).
		Str(string(LogFieldHandler), string(LogHandlerStartup)).
		Str(string(LogFieldOIDCIssuer), s.Config.OIDCIssuerURL).
		Str(string(LogFieldOIDCClientID), s.Config.OIDCClientID).
		Str(string(LogFieldOIDCClaimPolicy), string(s.Config.OIDCClaimPolicy)).
		Bool(string(LogFieldOIDCCAConfigured), strings.TrimSpace(s.Config.OIDCCAPath) != "").
		Str(string(LogFieldFailureCategory), string(category)).
		Str(string(LogFieldProviderOp), operation).
		Err(err).
		Msg(string(LogEventOIDCProviderValidationFailed))
}

func classifyProviderValidationFailure(err error, fallback LogFailureCategory) LogFailureCategory {
	if err == nil {
		return fallback
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return LogFailureDNSLookup
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return LogFailureTLSValidation
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return LogFailureConnectionTimeout
	}
	if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
		return LogFailureConnectionRefused
	}
	if fallback == LogFailureJWKSUnavailable && providerErrorCauseContains(err, "parse jwks") {
		return LogFailureJWKSInvalid
	}
	if errors.Is(err, oidc.ErrProviderMetadata) && fallback != LogFailureJWKSUnavailable {
		return LogFailureProviderMetadata
	}
	return fallback
}

func providerErrorCauseContains(err error, needle string) bool {
	needle = strings.ToLower(needle)
	if strings.Contains(strings.ToLower(err.Error()), needle) {
		return true
	}
	var providerErr *oidc.ProviderError
	if errors.As(err, &providerErr) && providerErr.Cause != nil {
		return strings.Contains(strings.ToLower(providerErr.Cause.Error()), needle)
	}
	return false
}

func providerOperation(err error, fallback string) string {
	var providerErr *oidc.ProviderError
	if errors.As(err, &providerErr) && providerErr.Operation != "" {
		return providerErr.Operation
	}
	return fallback
}

func introspectionEndpointSource(metadata *oidc.ProviderMetadata) string {
	if metadata != nil && strings.TrimSpace(metadata.TokenIntrospectionEndpoint) != "" {
		return "token_introspection_endpoint"
	}
	return "introspection_endpoint"
}

func jwksKeyCount(jwks interface{}) int {
	jwksMap, ok := jwks.(map[string]interface{})
	if !ok {
		return 0
	}
	keys, ok := jwksMap["keys"].([]interface{})
	if !ok {
		return 0
	}
	return len(keys)
}

func validJWKS(jwks interface{}) bool {
	jwksMap, ok := jwks.(map[string]interface{})
	if !ok {
		return false
	}
	keys, ok := jwksMap["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		keyMap, ok := key.(map[string]interface{})
		if !ok {
			return false
		}
		for _, field := range []string{"kid", "kty", "n", "e"} {
			value, ok := keyMap[field].(string)
			if !ok || strings.TrimSpace(value) == "" {
				return false
			}
		}
		if keyMap["kty"] != "RSA" {
			return false
		}
	}
	return true
}
