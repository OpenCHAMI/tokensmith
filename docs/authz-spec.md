<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith AuthN/AuthZ Wire Contract Spec (Frozen)

This document is the **source of truth** for TokenSmith HTTP authentication (JWT) and authorization (Casbin) middleware **wire behavior**.

The words **MUST**, **SHOULD**, **MAY**, **MUST NOT**, and **SHOULD NOT** are to be interpreted as described in RFC 2119.

If there is a conflict between this document and implementation details elsewhere in the repo, **this document wins**.

## 0. Scope

This spec freezes:

- The deny JSON schema and extensibility policy
- HTTP status / header / body semantics for AuthN/AuthZ middleware
- Request normalization used for path/method-style authorization
- AuthZ decision semantics across modes (`OFF`, `SHADOW`, `ENFORCE`)
- JWT validation minimum safe defaults
- JWKS caching and failure semantics

Non-goals:

- Defining service-specific object/action taxonomies
- Hiding Casbin: services and operators are expected to work with Casbin model/policy files directly

## 1. Deny JSON schema v1 (authz.deny.v1)

### 1.1 Media type

TokenSmith deny responses MUST be JSON and MUST set:

- `Content-Type: application/json; charset=utf-8`

TokenSmith MUST ignore the request `Accept` header (i.e., content negotiation is not supported for denies).

### 1.2 Schema

On a deny response (whether AuthN or AuthZ is the root cause), TokenSmith MUST respond with a JSON object matching the following schema.

#### 1.2.1 Top-level fields

Required fields:

- `schema_version` (string) — MUST equal exactly `"authz.deny.v1"`.
- `code` (string) — stable, machine-readable TokenSmith-owned code.
- `message` (string) — stable, human-readable summary; MUST NOT include sensitive values.
- `decision` (string enum) — `"allow"` | `"deny"`.
- `reason` (string enum) — see §1.2.2.
- `mode` (string enum) — `"OFF"` | `"SHADOW"` | `"ENFORCE"`.
- `principal` (object) — see §1.2.3.
- `input` (object) — see §1.2.4.
- `policy_version` (string) — deterministic hash of effective policy inputs; MUST be present even if empty/unknown.
- `request` (object) — see §1.2.5.

Optional fields:

- `request_id` (string) — included if present in context (see implementation docs).
- `details` (object) — additional non-sensitive machine-readable detail.

Extensibility policy:

- TokenSmith MAY add new **optional** fields in future versions.
- TokenSmith MUST NOT change the meaning of existing fields within `authz.deny.v1`.
- Consumers MUST ignore unknown fields.

#### 1.2.2 `reason` enum

`reason` MUST be one of:

- `no_principal` — no authenticated principal was available but authorization required.
- `invalid_token` — an Authorization header was present but token validation failed.
- `policy_denied` — Casbin evaluated successfully and denied the request.
- `unmapped_route` — request could not be mapped into a Casbin input tuple and deny-by-default applied.
- `engine_error` — internal AuthZ engine error (Casbin/model/policy/runtime errors).
- `bad_request` — request normalization failed deterministically (see §3.3).

#### 1.2.3 `principal`

`principal` MUST be an object with the following fields:

Required:

- `id` (string) — stable identifier for the principal; empty string if unknown.
- `type` (string) — stable principal type string (e.g., `"user"`, `"service"`, `"unknown"`).

Optional:

- `roles` (array of strings) — MAY be present.

Redaction rules:

- TokenSmith MUST NOT include raw JWTs.
- TokenSmith MUST NOT include arbitrary claims.
- `roles` MUST only contain role/group identifiers that are already considered non-sensitive in OpenCHAMI deployments.
- If role/group content is considered sensitive for an integration, the service SHOULD configure TokenSmith to omit role lists (implementation detail), but schema support remains.

#### 1.2.4 `input`

`input` MUST be an object:

Required:

- `object` (string)
- `action` (string)

Optional:

- `domain` (string)

Notes:

- When a request is public-bypassed, TokenSmith MUST NOT emit a deny response.
- When a request is unmapped, `object` and `action` MUST still be present; they SHOULD be set to empty strings.

#### 1.2.5 `request`

`request` MUST be an object:

Required:

- `method` (string) — HTTP method as received.
- `path` (string) — normalized path used for evaluation/logging (see §3).

### 1.3 `code` values

TokenSmith `code` MUST be one of the following in v1:

- `AUTHN_REQUIRED`
- `AUTHN_INVALID`
- `AUTHZ_DENIED`
- `AUTHZ_UNMAPPED`
- `AUTHZ_ENGINE_ERROR`
- `BAD_REQUEST`

(Implementations MAY add new codes in a backwards-compatible way.)

### 1.4 HEAD behavior

For `HEAD` requests:

- TokenSmith MUST set the HTTP status code and headers as usual.
- TokenSmith MUST NOT write a response body.

## 2. HTTP semantics

### 2.1 Status mapping

TokenSmith middleware MUST map denial causes to HTTP status codes as follows:

- **401 Unauthorized**
  - `reason=no_principal` when authentication is required
  - `reason=invalid_token`

- **403 Forbidden**
  - `reason=policy_denied`
  - `reason=unmapped_route`

- **400 Bad Request**
  - `reason=bad_request`

- **500 Internal Server Error**
  - `reason=engine_error`

### 2.2 Short-circuit semantics

When TokenSmith denies a request:

- The middleware MUST NOT call the downstream handler (`next`).
- The middleware MUST write headers/status/body (unless `HEAD`).

If headers have already been written (mis-ordered middleware):

- TokenSmith MUST make a best-effort to log a warning.
- TokenSmith MUST NOT panic.
- TokenSmith SHOULD avoid writing a second response body.

## 3. Request normalization (path/method style)

This section applies when TokenSmith is configured to use Casbin-native path/method style inputs.

### 3.1 Path source

The path input MUST be taken from:

1. `r.URL.EscapedPath()` if it returns a non-empty string
2. Otherwise, the literal string `"/"`

Query strings MUST be excluded.

### 3.2 Malformed escapes

If `r.URL.EscapedPath()` returns a value that cannot be safely unescaped/normalized by TokenSmith (implementation-defined), TokenSmith MUST treat the request as:

- `reason=bad_request` and respond with HTTP 400.

Rationale: deterministic behavior that fails closed and avoids policy bypass via ambiguous decoding.

### 3.3 Method normalization

TokenSmith MUST support at least two method→action modes:

- `literal`: `action = r.Method`
- `rest`: `GET`/`HEAD` → `read`; `POST`/`PUT`/`PATCH` → `write`; `DELETE` → `delete`; other methods → method literal

### 3.4 OPTIONS / CORS

Default behavior:

- TokenSmith MUST treat `OPTIONS` requests as **public-bypassed** by default.

Integration note:

- If a service installs a CORS middleware that handles `OPTIONS` automatically, the service MAY place CORS middleware before TokenSmith.

## 4. AuthZ decision semantics (modes)

### 4.1 Definitions

Inputs to the decision matrix:

- `mode`: `OFF` | `SHADOW` | `ENFORCE`
- `public`: route classified as public (bypass)
- `mapped`: request mapped to `(object, action[, domain])`
- `principal`: authenticated principal present
- `engine_error`: error during evaluation (including Casbin/model/policy runtime errors)

Outputs:

- `evaluate`: whether Casbin evaluation MUST occur
- `allow`: whether the request MUST be allowed to proceed
- `http_status`: if denied, the HTTP status
- `reason`: if denied (or logged in shadow), the reason code

### 4.2 Decision matrix

Rules are applied in order; first match wins.

| Priority | Mode     | Public | Principal | Mapped | Engine error | Evaluate | Result  | HTTP | Reason |
|----------|----------|--------|-----------|--------|--------------|----------|---------|------|--------|
| 1        | any      | true   | any       | any    | any          | no       | allow   | n/a  | n/a    |
| 2        | OFF      | false  | any       | any    | any          | no       | allow   | n/a  | n/a    |
| 3        | SHADOW   | false  | false     | any    | any          | no       | allow   | n/a  | no_principal (log) |
| 4        | ENFORCE  | false  | false     | any    | any          | no       | deny    | 401  | no_principal |
| 5        | SHADOW   | false  | true      | false  | any          | no       | allow   | n/a  | unmapped_route (log) |
| 6        | ENFORCE  | false  | true      | false  | any          | no       | deny    | 403  | unmapped_route |
| 7        | SHADOW   | false  | true      | true   | true         | yes      | allow   | n/a  | engine_error (log) |
| 8        | ENFORCE  | false  | true      | true   | true         | yes      | deny    | 500  | engine_error |
| 9        | SHADOW   | false  | true      | true   | false        | yes      | allow   | n/a  | policy_denied (log if denied) |
| 10       | ENFORCE  | false  | true      | true   | false        | yes      | allow/deny | 403 if deny | policy_denied |

Notes:

- In SHADOW mode, TokenSmith MUST log decisions for mapped requests and SHOULD log for unmapped/missing principal.
- In ENFORCE mode, deny-by-default applies to unmapped routes unless explicitly configured otherwise (configuration is an implementation detail but MUST be testable).

## 5. AuthN/JWT minimum safe defaults

TokenSmith JWT validation MUST, by default:

- Validate signature
- Validate `exp` and `nbf` when present
- Require and validate `iss` (issuer)
- Require and validate `aud` (audience)

Opt-outs:

- Any opt-out from issuer or audience validation MUST be explicit in configuration.

Clock skew:

- Default allowed clock skew MUST be `2m`.
- Maximum allowed clock skew MUST be `10m`; configuration above this MUST be rejected (fail fast).

## 6. JWKS caching and failure semantics

### 6.1 Cache model

TokenSmith maintains an in-memory cache of JWKS keys per configured JWKS URL.

- Cache entries have a TTL (default `15m`, configurable).
- TokenSmith MUST attempt to refresh keys when TTL expires.

### 6.2 Last-known-good behavior

- If the cache is populated (last-known-good keys exist) and a refresh attempt fails, TokenSmith MUST continue to use the cached keys until a **hard expiry** time of `24h` since last successful refresh.
- After hard expiry, TokenSmith MUST treat the cache as empty.

### 6.3 Fail-closed behavior

- If no valid cached keys are available and JWKS fetch fails, TokenSmith MUST reject tokens that require those keys.

### 6.4 Background refresh

Implementations MAY refresh keys asynchronously; however, observed validation behavior MUST be consistent with §6.2–§6.3.
