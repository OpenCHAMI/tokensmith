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
	LogFieldComponent       LogField = "component"
	LogFieldEvent           LogField = "event"
	LogFieldAuditEvent      LogField = "audit_event"
	LogFieldHandler         LogField = "handler"
	LogFieldRequestID       LogField = "request_id"
	LogFieldClientIP        LogField = "client_ip"
	LogFieldSubject         LogField = "subject"
	LogFieldAudience        LogField = "audience"
	LogFieldFailureCategory LogField = "failure_category"
	LogFieldFailureStage    LogField = "failure_stage"
	LogFieldProviderOp      LogField = "provider_operation"
	LogFieldTokenHashPrefix LogField = "token_hash_prefix"
	LogFieldRefreshFamilyID LogField = "refresh_family_id"
	LogFieldPolicyVersion   LogField = "policy_version"
	LogFieldOIDCIssuer      LogField = "oidc_issuer"
	LogFieldOIDCClientID    LogField = "oidc_client_id"
	LogFieldOIDCClaimPolicy LogField = "oidc_claim_policy"
	LogFieldUpstreamStatus  LogField = "upstream_status_code"
	LogFieldRequestedScopes LogField = "requested_scopes"
	LogFieldDerivedScopes   LogField = "derived_scopes"
	LogFieldRejectedScope   LogField = "rejected_scope"
	LogFieldTargetService   LogField = "target_service"
)

const (
	LogEventTokenSmithStarted             LogEvent = "tokensmith_started"
	LogEventOIDCProviderValidationStarted LogEvent = "oidc_provider_validation_started"
	LogEventOIDCProviderValidationOK      LogEvent = "oidc_provider_validation_succeeded"
	LogEventOIDCProviderValidationFailed  LogEvent = "oidc_provider_validation_failed"
	LogEventTokenExchangeSucceeded        LogEvent = "token_exchange_succeeded"
	LogEventTokenExchangeFailed           LogEvent = "token_exchange_failed"
	LogEventBootstrapTokenCreated         LogEvent = "bootstrap_token_created"
	LogEventBootstrapTokenExchanged       LogEvent = "bootstrap_token_exchanged"
	LogEventRefreshTokenRotated           LogEvent = "refresh_token_rotated"
	LogEventRefreshReplayDetected         LogEvent = "refresh_token_replay_detected"
	LogEventServiceIdentitySessionOK      LogEvent = "service_identity_session_succeeded"
	LogEventServiceIdentitySessionFailed  LogEvent = "service_identity_session_failed"
)

const (
	LogHandlerStartup                LogHandler = "startup"
	LogHandlerOAuthExchange          LogHandler = "oauth_exchange"
	LogHandlerOAuthToken             LogHandler = "oauth_token"
	LogHandlerServiceIdentitySession LogHandler = "service_identity_session"
	LogHandlerOIDCAdmin              LogHandler = "oidc_admin"
)

const (
	LogFailureDNSLookup                LogFailureCategory = "dns_lookup_failed"
	LogFailureTLSValidation            LogFailureCategory = "tls_validation_failed"
	LogFailureConnectionRefused        LogFailureCategory = "connection_refused"
	LogFailureConnectionTimeout        LogFailureCategory = "connection_timeout"
	LogFailureProviderMetadata         LogFailureCategory = "provider_metadata"
	LogFailureJWKSUnavailable          LogFailureCategory = "jwks_unavailable"
	LogFailureJWKSInvalid              LogFailureCategory = "jwks_invalid"
	LogFailureClientConfigMissing      LogFailureCategory = "client_config_missing"
	LogFailureInvalidToken             LogFailureCategory = "invalid_token"
	LogFailureInactiveToken            LogFailureCategory = "inactive_token"
	LogFailureMissingClaim             LogFailureCategory = "missing_claim"
	LogFailureInvalidClaim             LogFailureCategory = "invalid_claim"
	LogFailureGeneratedClaimValidation LogFailureCategory = "generated_claim_validation"
	LogFailureScopeNotGranted          LogFailureCategory = "scope_not_granted"
	LogFailureBootstrapTokenNotFound   LogFailureCategory = "bootstrap_token_not_found"
	LogFailureBootstrapTokenExpired    LogFailureCategory = "bootstrap_token_expired"
	LogFailureBootstrapTokenConsumed   LogFailureCategory = "bootstrap_token_consumed"
	LogFailureRefreshTokenNotFound     LogFailureCategory = "refresh_token_not_found"
	LogFailureRefreshFamilyExpired     LogFailureCategory = "refresh_family_expired"
	LogFailureRefreshReplayDetected    LogFailureCategory = "refresh_replay_detected"
)

const (
	ForbiddenLogFieldRawJWT                    LogField = "raw_jwt"
	ForbiddenLogFieldAccessToken               LogField = "access_token"
	ForbiddenLogFieldBootstrapToken            LogField = "bootstrap_token"
	ForbiddenLogFieldRefreshToken              LogField = "refresh_token"
	ForbiddenLogFieldOIDCClientSecret          LogField = "oidc_client_secret"
	ForbiddenLogFieldAuthorization             LogField = "authorization"
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
