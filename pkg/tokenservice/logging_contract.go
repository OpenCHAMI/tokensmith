// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

// LogField names a structured TokenSmith log field.
type LogField string

// LogEvent names a stable operational TokenSmith log event.
type LogEvent string

// LogHandler names the TokenSmith subsystem or HTTP handler emitting a log.
type LogHandler string

// LogFailureCategory names the safe, bounded reason class for a failed operation.
type LogFailureCategory string

const (
	// LogFieldComponent identifies the TokenSmith component that emitted the log.
	LogFieldComponent LogField = "component"
	// LogFieldEvent names the operational event for non-audit lifecycle logs.
	LogFieldEvent LogField = "event"
	// LogFieldAuditEvent names the security or audit event recorded by the log.
	LogFieldAuditEvent LogField = "audit_event"
	// LogFieldHandler identifies the HTTP handler or subsystem handling the operation.
	LogFieldHandler LogField = "handler"
	// LogFieldRequestID carries the request correlation ID when one is available.
	LogFieldRequestID LogField = "request_id"
	// LogFieldClientIP records the client IP or socket peer used for troubleshooting.
	LogFieldClientIP LogField = "client_ip"
	// LogFieldSubject records the authenticated principal or target subject.
	LogFieldSubject LogField = "subject"
	// LogFieldAudience records the token audience or downstream target service.
	LogFieldAudience LogField = "audience"
	// LogFieldFailureCategory records a stable bounded reason class for failures.
	LogFieldFailureCategory LogField = "failure_category"
	// LogFieldFailureStage identifies the operation stage where a failure happened.
	LogFieldFailureStage LogField = "failure_stage"
	// LogFieldProviderOp names the upstream provider operation being attempted.
	LogFieldProviderOp LogField = "provider_operation"
	// LogFieldTokenHashPrefix correlates opaque token attempts using a bounded hash prefix.
	LogFieldTokenHashPrefix LogField = "token_hash_prefix"
	// LogFieldRefreshFamilyID identifies the refresh-token family without logging tokens.
	LogFieldRefreshFamilyID LogField = "refresh_family_id"
	// LogFieldPolicyVersion records the authz policy version or hash used for a decision.
	LogFieldPolicyVersion LogField = "policy_version"
	// LogFieldOIDCIssuer records the configured upstream OIDC issuer URL.
	LogFieldOIDCIssuer LogField = "oidc_issuer"
	// LogFieldOIDCClientID records the configured upstream OIDC client ID.
	LogFieldOIDCClientID LogField = "oidc_client_id"
	// LogFieldOIDCClaimPolicy records the claim policy used to map upstream OIDC claims.
	LogFieldOIDCClaimPolicy LogField = "oidc_claim_policy"
	// LogFieldUpstreamStatus records a non-secret HTTP status from an upstream dependency.
	LogFieldUpstreamStatus LogField = "upstream_status_code"
	// LogFieldRequestedScopes records scopes requested by the caller.
	LogFieldRequestedScopes LogField = "requested_scopes"
	// LogFieldDerivedScopes records scopes derived from trusted policy or upstream claims.
	LogFieldDerivedScopes LogField = "derived_scopes"
	// LogFieldRejectedScope records the single requested scope rejected by policy.
	LogFieldRejectedScope LogField = "rejected_scope"
	// LogFieldTargetService records the requested downstream OpenCHAMI service audience.
	LogFieldTargetService LogField = "target_service"
)

const (
	// LogEventTokenSmithStarted records the effective startup configuration after parsing.
	LogEventTokenSmithStarted LogEvent = "tokensmith_started"
	// LogEventOIDCProviderValidationStarted records the beginning of an OIDC startup probe.
	LogEventOIDCProviderValidationStarted LogEvent = "oidc_provider_validation_started"
	// LogEventOIDCProviderValidationOK records successful OIDC discovery or JWKS validation.
	LogEventOIDCProviderValidationOK LogEvent = "oidc_provider_validation_succeeded"
	// LogEventOIDCProviderValidationFailed records failed OIDC discovery or JWKS validation.
	LogEventOIDCProviderValidationFailed LogEvent = "oidc_provider_validation_failed"
	// LogEventTokenExchangeSucceeded records a successful upstream token exchange.
	LogEventTokenExchangeSucceeded LogEvent = "token_exchange_succeeded"
	// LogEventTokenExchangeFailed records a failed upstream token exchange.
	LogEventTokenExchangeFailed LogEvent = "token_exchange_failed"
	// LogEventBootstrapTokenCreated records creation of a one-time bootstrap token policy.
	LogEventBootstrapTokenCreated LogEvent = "bootstrap_token_created"
	// LogEventBootstrapTokenExchanged records successful bootstrap token redemption.
	LogEventBootstrapTokenExchanged LogEvent = "bootstrap_token_exchanged"
	// LogEventRefreshTokenRotated records successful refresh-token rotation.
	LogEventRefreshTokenRotated LogEvent = "refresh_token_rotated"
	// LogEventRefreshReplayDetected records attempted reuse of an old refresh token.
	LogEventRefreshReplayDetected LogEvent = "refresh_token_replay_detected"
	// LogEventServiceIdentitySessionOK records successful mTLS service-identity exchange.
	LogEventServiceIdentitySessionOK LogEvent = "service_identity_session_succeeded"
	// LogEventServiceIdentitySessionFailed records failed mTLS service-identity exchange.
	LogEventServiceIdentitySessionFailed LogEvent = "service_identity_session_failed"
)

const (
	// LogHandlerStartup identifies startup and configuration validation logs.
	LogHandlerStartup LogHandler = "startup"
	// LogHandlerOAuthExchange identifies POST /oauth/exchange OIDC exchange logs.
	LogHandlerOAuthExchange LogHandler = "oauth_exchange"
	// LogHandlerOAuthToken identifies POST /oauth/token bootstrap and refresh logs.
	LogHandlerOAuthToken LogHandler = "oauth_token"
	// LogHandlerServiceIdentitySession identifies POST /service-identity/session logs.
	LogHandlerServiceIdentitySession LogHandler = "service_identity_session"
	// LogHandlerOIDCAdmin identifies local runtime OIDC admin endpoint logs.
	LogHandlerOIDCAdmin LogHandler = "oidc_admin"
)

const (
	// LogFailureDNSLookup means upstream name resolution failed.
	LogFailureDNSLookup LogFailureCategory = "dns_lookup_failed"
	// LogFailureTLSValidation means upstream TLS certificate validation failed.
	LogFailureTLSValidation LogFailureCategory = "tls_validation_failed"
	// LogFailureConnectionRefused means the upstream endpoint actively refused connection.
	LogFailureConnectionRefused LogFailureCategory = "connection_refused"
	// LogFailureConnectionTimeout means an upstream network operation exceeded its deadline.
	LogFailureConnectionTimeout LogFailureCategory = "connection_timeout"
	// LogFailureProviderMetadata means OIDC discovery metadata was missing or invalid.
	LogFailureProviderMetadata LogFailureCategory = "provider_metadata"
	// LogFailureJWKSUnavailable means TokenSmith could not retrieve upstream JWKS.
	LogFailureJWKSUnavailable LogFailureCategory = "jwks_unavailable"
	// LogFailureJWKSInvalid means upstream JWKS was retrieved but could not be used.
	LogFailureJWKSInvalid LogFailureCategory = "jwks_invalid"
	// LogFailureClientConfigMissing means required local OIDC client config is absent.
	LogFailureClientConfigMissing LogFailureCategory = "client_config_missing"
	// LogFailureInvalidToken means the upstream token failed structural or trust validation.
	LogFailureInvalidToken LogFailureCategory = "invalid_token"
	// LogFailureInactiveToken means upstream introspection reported active=false.
	LogFailureInactiveToken LogFailureCategory = "inactive_token"
	// LogFailureMissingClaim means a required claim name was absent from mapped claims.
	LogFailureMissingClaim LogFailureCategory = "missing_claim"
	// LogFailureInvalidClaim means a present or derived claim could not satisfy policy.
	LogFailureInvalidClaim LogFailureCategory = "invalid_claim"
	// LogFailureGeneratedClaimValidation means generated TokenSmith claims failed validation.
	LogFailureGeneratedClaimValidation LogFailureCategory = "generated_claim_validation"
	// LogFailureScopeNotGranted means requested scopes exceeded derived allowed scopes.
	LogFailureScopeNotGranted LogFailureCategory = "scope_not_granted"
	// LogFailureBootstrapTokenNotFound means no bootstrap policy matched the token hash.
	LogFailureBootstrapTokenNotFound LogFailureCategory = "bootstrap_token_not_found"
	// LogFailureBootstrapTokenExpired means the matched bootstrap policy is expired.
	LogFailureBootstrapTokenExpired LogFailureCategory = "bootstrap_token_expired"
	// LogFailureBootstrapTokenConsumed means the bootstrap token was already redeemed.
	LogFailureBootstrapTokenConsumed LogFailureCategory = "bootstrap_token_consumed"
	// LogFailureRefreshTokenNotFound means no refresh family matched the token hash.
	LogFailureRefreshTokenNotFound LogFailureCategory = "refresh_token_not_found"
	// LogFailureRefreshFamilyExpired means the matched refresh family has expired.
	LogFailureRefreshFamilyExpired LogFailureCategory = "refresh_family_expired"
	// LogFailureRefreshReplayDetected means an old refresh token was reused.
	LogFailureRefreshReplayDetected LogFailureCategory = "refresh_replay_detected"
)

const (
	// ForbiddenLogFieldRawJWT marks raw JWT payload logging as forbidden.
	ForbiddenLogFieldRawJWT LogField = "raw_jwt"
	// ForbiddenLogFieldAccessToken marks raw TokenSmith access token logging as forbidden.
	ForbiddenLogFieldAccessToken LogField = "access_token"
	// ForbiddenLogFieldBootstrapToken marks raw bootstrap token logging as forbidden.
	ForbiddenLogFieldBootstrapToken LogField = "bootstrap_token"
	// ForbiddenLogFieldRefreshToken marks raw refresh token logging as forbidden.
	ForbiddenLogFieldRefreshToken LogField = "refresh_token"
	// ForbiddenLogFieldOIDCClientSecret marks upstream OIDC client secret logging as forbidden.
	ForbiddenLogFieldOIDCClientSecret LogField = "oidc_client_secret"
	// ForbiddenLogFieldAuthorization marks full Authorization header logging as forbidden.
	ForbiddenLogFieldAuthorization LogField = "authorization"
	// ForbiddenLogFieldUpstreamIntrospectionBody marks full introspection response logging as forbidden.
	ForbiddenLogFieldUpstreamIntrospectionBody LogField = "upstream_introspection_response"
)

func loggingContractFields() []LogField {
	return []LogField{
		LogFieldComponent,
		LogFieldEvent,
		LogFieldAuditEvent,
		LogFieldHandler,
		LogFieldRequestID,
		LogFieldClientIP,
		LogFieldSubject,
		LogFieldAudience,
		LogFieldFailureCategory,
		LogFieldFailureStage,
		LogFieldProviderOp,
		LogFieldTokenHashPrefix,
		LogFieldRefreshFamilyID,
		LogFieldPolicyVersion,
		LogFieldOIDCIssuer,
		LogFieldOIDCClientID,
		LogFieldOIDCClaimPolicy,
		LogFieldUpstreamStatus,
		LogFieldRequestedScopes,
		LogFieldDerivedScopes,
		LogFieldRejectedScope,
		LogFieldTargetService,
	}
}

func loggingContractEvents() []LogEvent {
	return []LogEvent{
		LogEventTokenSmithStarted,
		LogEventOIDCProviderValidationStarted,
		LogEventOIDCProviderValidationOK,
		LogEventOIDCProviderValidationFailed,
		LogEventTokenExchangeSucceeded,
		LogEventTokenExchangeFailed,
		LogEventBootstrapTokenCreated,
		LogEventBootstrapTokenExchanged,
		LogEventRefreshTokenRotated,
		LogEventRefreshReplayDetected,
		LogEventServiceIdentitySessionOK,
		LogEventServiceIdentitySessionFailed,
	}
}

func loggingContractHandlers() []LogHandler {
	return []LogHandler{
		LogHandlerStartup,
		LogHandlerOAuthExchange,
		LogHandlerOAuthToken,
		LogHandlerServiceIdentitySession,
		LogHandlerOIDCAdmin,
	}
}

func loggingContractFailureCategories() []LogFailureCategory {
	return []LogFailureCategory{
		LogFailureDNSLookup,
		LogFailureTLSValidation,
		LogFailureConnectionRefused,
		LogFailureConnectionTimeout,
		LogFailureProviderMetadata,
		LogFailureJWKSUnavailable,
		LogFailureJWKSInvalid,
		LogFailureClientConfigMissing,
		LogFailureInvalidToken,
		LogFailureInactiveToken,
		LogFailureMissingClaim,
		LogFailureInvalidClaim,
		LogFailureGeneratedClaimValidation,
		LogFailureScopeNotGranted,
		LogFailureBootstrapTokenNotFound,
		LogFailureBootstrapTokenExpired,
		LogFailureBootstrapTokenConsumed,
		LogFailureRefreshTokenNotFound,
		LogFailureRefreshFamilyExpired,
		LogFailureRefreshReplayDetected,
	}
}

func forbiddenLogFields() []LogField {
	return []LogField{
		ForbiddenLogFieldRawJWT,
		ForbiddenLogFieldAccessToken,
		ForbiddenLogFieldBootstrapToken,
		ForbiddenLogFieldRefreshToken,
		ForbiddenLogFieldOIDCClientSecret,
		ForbiddenLogFieldAuthorization,
		ForbiddenLogFieldUpstreamIntrospectionBody,
	}
}
