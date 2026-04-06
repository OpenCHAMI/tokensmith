<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith security & threat model notes

This document captures security-relevant behavior for TokenSmith AuthN (JWT) and AuthZ (Casbin) middleware.

It is a companion to the frozen wire contract:

- `docs/authz-spec.md`

## Threat model (high level)

TokenSmith assumes:

- The service process is running in a trusted environment (e.g., Kubernetes pod).
- Policy files mounted into the service are trusted deploy-time configuration.
- Callers are untrusted and may:
  - send malformed requests
  - replay tokens
  - attempt algorithm confusion or header manipulation
  - attempt to bypass policy via path encoding/normalization tricks

TokenSmith mitigations focus on:

- fail-closed defaults
- deterministic normalization
- minimizing sensitive data exposure in logs and responses

AuthN in `pkg/authn` validates TokenSmith JWTs against the current TokenSmith claim contract. The required claim set includes `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `auth_level`, `auth_factors`, `auth_methods`, `session_id`, `session_exp`, and `auth_events`.

## JWT handling: logging and redaction

- TokenSmith **MUST NOT log raw JWTs**.
- TokenSmith deny responses **MUST NOT echo** Authorization headers or arbitrary JWT claims.
- Principal summaries in logs/deny bodies should contain only:
  - `principal.id`, `principal.type`, and optionally `principal.roles`

If your environment considers roles sensitive, configure TokenSmith to omit role lists in logs.

## Key IDs (`kid`) and key binding

TokenSmith uses RFC 7638 JWK thumbprints (SHA-256, base64url) as JWT `kid` values.

AuthN middleware in `pkg/authn` enforces that:

- JWT header `kid` is present
- `kid` format is RFC 7638-compliant
- key lookup is performed by `kid` (JWKS/static key matching)

Rationale: requiring deterministic key IDs prevents ambiguous static-key fallback and ensures verification binds to the intended signing key.

## Issuer/audience defaults

Per `docs/authz-spec.md`:

- By default TokenSmith JWT validation **requires** and validates:
  - `iss` (issuer)
  - `aud` (audience)

Any opt-out must be explicit in configuration.

Rationale: missing `iss`/`aud` validation is a common misconfiguration that leads to token acceptance from unexpected issuers or for unexpected audiences.

## Algorithm allowlist & confusion risks

JWT validation MUST:

- enforce an **algorithm allowlist** appropriate to the key material (e.g., RS256 for RSA keys)
- reject tokens using `alg=none`
- avoid key confusion between symmetric (HS*) and asymmetric (RS*/ES*) algorithms

If you configure multiple issuers/JWKS sources, ensure they are scoped by issuer/audience as appropriate.

## JWKS caching and availability risks

### What can go wrong

- JWKS endpoint outage can prevent new keys from being fetched.
- Stale caches can accept tokens signed by keys that should have been rotated out.
- Aggressive fail-open behaviors can cause accidental allow.

### TokenSmith behavior

TokenSmith uses **last-known-good caching** with **fail-closed** semantics (see `docs/authz-spec.md`):

- When cached keys exist and refresh fails, TokenSmith continues to use cached keys up to a hard-expiry.
- When no valid cached keys exist and fetch fails, TokenSmith rejects tokens that require those keys.

Operational guidance:

- monitor JWKS fetch errors
- prefer highly-available JWKS endpoints
- ensure your key rotation cadence is compatible with cache TTLs

## Policy loading trust boundary

- Policy files are not signed/verified by TokenSmith in v1.
- Treat the policy directory as trusted configuration (ConfigMap/Secret/volume managed by cluster admins).

If an attacker can modify policy files on disk, they can change authorization decisions.

## Path normalization and policy bypass risks

Path/method style authorization depends on deterministic path normalization.

- TokenSmith must avoid ambiguous decoding.
- Malformed escapes should fail deterministically with a 400 (`reason=bad_request`).

Rationale: inconsistent decoding between routers/middlewares can allow attackers to hit a protected handler while the authorizer evaluates a different path.

## Fail-closed behavior summary

- Policy/model load failures at startup: **fail-fast** (process should not start).
- Runtime engine errors in `ENFORCE`: deny with a stable error response.
- Missing/invalid tokens when authn is required: deny (401) with stable error response.
