<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith logging contract

This contract defines the stable structured fields, event names, failure categories, and redaction rules TokenSmith logs should follow. It is the standard for future startup, OIDC exchange, bootstrap-token, refresh-token, service-identity, and audit logging work.

## Scope

This document defines names and safety rules only. It does not require every current TokenSmith log line to conform immediately. Runtime logging changes should be made in follow-up work after this contract is accepted.

## Base fields

Every structured TokenSmith log should use stable snake_case fields. Use the same field name for the same concept across startup, request handlers, stores, and audit logs.

| Field | Use |
| --- | --- |
| `component` | Service component emitting the log. Use `tokenservice` for TokenSmith service logs. |
| `event` | Stable operational event name. Prefer this for non-audit operational logs. |
| `audit_event` | Stable security/audit event name. Use when the log records an auditable auth/security event. |
| `handler` | HTTP handler or subsystem handling the operation. |
| `request_id` | Request correlation ID when present. |
| `client_ip` | Client IP or socket peer used for troubleshooting and audit correlation. |
| `subject` | Authenticated or target subject. |
| `audience` | Token audience or target service. |
| `issuer` | TokenSmith issuer used in generated tokens. |
| `cluster_id` | OpenCHAMI cluster identifier used in generated tokens. |
| `openchami_id` | OpenCHAMI instance identifier used in generated tokens. |
| `failure_category` | Stable bounded reason class for a failed operation. |
| `failure_stage` | Stable stage name where the failure occurred. |
| `provider_operation` | Upstream provider operation, such as metadata fetch or token introspection. |
| `metadata_issuer` | Issuer returned by upstream OIDC discovery metadata. |
| `introspection_endpoint_source` | Discovery metadata key used for token introspection, such as `token_introspection_endpoint`. |
| `jwks_key_count` | Number of keys found in upstream JWKS during provider validation. |
| `token_hash_prefix` | Bounded hash prefix for correlating opaque token attempts. |
| `refresh_family_id` | Refresh-token family identifier. |
| `policy_version` | Authorization policy version or policy hash where available. |
| `oidc_issuer` | Configured upstream OIDC issuer. |
| `oidc_client_id` | Configured upstream OIDC client ID. |
| `oidc_claim_policy` | Configured upstream OIDC claim policy. |
| `oidc_ca_configured` | Whether a custom upstream OIDC CA bundle is configured. |
| `max_exchange_session_lifetime_seconds` | Configured cap for generated exchange-token sessions. |
| `bootstrap_store_path` | Configured bootstrap-token store path. |
| `refresh_store_path` | Configured refresh-token family store path. |
| `tls_enabled` | Whether TokenSmith is serving HTTPS. |
| `service_identity_mtls_enabled` | Whether inbound service-identity mTLS is enabled. |
| `local_user_mint_enabled` | Whether emergency local user token minting is enabled. |
| `listen_addr` | Local address TokenSmith is configured to serve on. |
| `upstream_status_code` | HTTP status returned by an upstream dependency. |
| `requested_scopes` | Scopes requested by the caller. |
| `derived_scopes` | Scopes derived from trusted TokenSmith policy or upstream claims. |
| `rejected_scope` | Single requested scope rejected by policy. |
| `target_service` | Requested downstream OpenCHAMI service audience. |

## Handler names

Use these handler names in the `handler` field:

| Handler | Use |
| --- | --- |
| `startup` | TokenSmith startup and configuration validation. |
| `oauth_exchange` | `POST /oauth/exchange` upstream OIDC token exchange. |
| `oauth_token` | `POST /oauth/token` bootstrap and refresh grants. |
| `service_identity_session` | `POST /service-identity/session` mTLS service-identity exchange. |
| `oidc_admin` | local runtime OIDC admin endpoints. |

## Event names

Operational event names should be stable and low-cardinality:

- `tokensmith_started`
- `oidc_provider_validation_started`
- `oidc_provider_validation_succeeded`
- `oidc_provider_validation_failed`
- `token_exchange_succeeded`
- `token_exchange_failed`
- `bootstrap_token_created`
- `bootstrap_token_exchanged`
- `refresh_token_rotated`
- `refresh_token_replay_detected`
- `service_identity_session_succeeded`
- `service_identity_session_failed`

For security/audit events, put the event name in `audit_event`. Logs may contain both `event` and `audit_event` when an operational event is also auditable.

## Failure categories

`failure_category` values must be stable reason classes, not raw error strings.

Startup and upstream OIDC categories:

- `dns_lookup_failed`
- `tls_validation_failed`
- `connection_refused`
- `connection_timeout`
- `provider_metadata`
- `jwks_unavailable`
- `jwks_invalid`
- `client_config_missing`

OIDC exchange categories:

- `invalid_token`
- `inactive_token`
- `missing_claim`
- `invalid_claim`
- `generated_claim_validation`
- `scope_not_granted`

Bootstrap and refresh categories:

- `bootstrap_token_not_found`
- `bootstrap_token_expired`
- `bootstrap_token_consumed`
- `refresh_token_not_found`
- `refresh_family_expired`
- `refresh_replay_detected`

## Forbidden fields

TokenSmith logs must not include raw credentials or full upstream security payloads. These field names are forbidden:

- `raw_jwt`
- `access_token`
- `bootstrap_token`
- `refresh_token`
- `oidc_client_secret`
- `authorization`
- `upstream_introspection_response`

Do not log these values under alternate field names. Use safe substitutes instead:

| Unsafe value | Safe substitute |
| --- | --- |
| raw JWT | JWT `jti` if available, otherwise a bounded hash prefix |
| raw bootstrap token | `token_hash_prefix` |
| raw refresh token | bounded hash prefix and `refresh_family_id` |
| OIDC client secret | `oidc_client_id` and provider operation result |
| Authorization header | `handler`, `client_ip`, `request_id`, and failure category |
| full introspection response | claim names, counts, source fields, and bounded reason codes |

## Safe examples

OIDC TLS failure:

```json
{
  "level": "warn",
  "component": "tokenservice",
  "event": "oidc_provider_validation_failed",
  "handler": "startup",
  "failure_category": "tls_validation_failed",
  "provider_operation": "get provider metadata",
  "oidc_issuer": "https://keycloak.example/realms/shasta",
  "oidc_client_id": "openchami-tokensmith"
}
```

Keycloak issuer mismatch:

```json
{
  "level": "warn",
  "component": "tokenservice",
  "audit_event": "token_exchange_failed",
  "handler": "oauth_exchange",
  "failure_category": "invalid_token",
  "failure_stage": "validate_upstream_token",
  "provider_operation": "validate local token",
  "oidc_claim_policy": "csm-keycloak"
}
```

Scope rejection:

```json
{
  "level": "warn",
  "component": "tokenservice",
  "audit_event": "token_exchange_failed",
  "handler": "oauth_exchange",
  "failure_category": "scope_not_granted",
  "requested_scopes": ["admin"],
  "derived_scopes": ["read"],
  "rejected_scope": "admin",
  "target_service": "smd"
}
```

Generated TokenSmith claim validation failure:

```json
{
  "level": "warn",
  "component": "tokenservice",
  "audit_event": "token_exchange_failed",
  "handler": "oauth_exchange",
  "failure_category": "generated_claim_validation",
  "failure_stage": "generate_token",
  "oidc_claim_policy": "csm-keycloak"
}
```

Refresh replay detection:

```json
{
  "level": "error",
  "component": "tokenservice",
  "audit_event": "refresh_token_replay_detected",
  "handler": "oauth_token",
  "failure_category": "refresh_replay_detected",
  "refresh_family_id": "family-123",
  "token_hash_prefix": "7dbfe3b6",
  "subject": "boot-service",
  "audience": "smd"
}
```

## Levels

Use levels by consumer action:

| Level | Use |
| --- | --- |
| `debug` | Developer-only details that are safe but too noisy for normal operation. |
| `info` | Normal lifecycle events and successful exchanges that admins may query. |
| `warn` | Caller/config/provider failures that need admin attention but do not indicate TokenSmith corruption. |
| `error` | TokenSmith internal failures, persistence failures, replay detections, or security conditions requiring investigation. |

## Legendary-funicular readiness

Logs should be easy to query as structured records in legendary-funicular. Prefer stable fields and low-cardinality event/category values so operators can filter by service, time range, event, handler, and failure category.
