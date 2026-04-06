<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith Authorization (AuthZ) Contract

This document defines the **normative** authorization contract for OpenCHAMI services using TokenSmith.

The words **MUST**, **SHOULD**, **MAY**, **MUST NOT**, and **SHOULD NOT** are to be interpreted as described in RFC 2119.

## 1. Scope

This contract specifies:

- Authorization modes and their failure behavior
- Core decision taxonomy for authorization evaluation
- A stable error response schema for AuthZ denials
- Route protection / deny-by-default expectations
- Identity/claims mapping expectations (principal model)
- Object/action mapping rules
- Policy version identity requirements (deterministic hash)

This contract is owned by **TokenSmith**. Services integrate by calling TokenSmith APIs/middleware as defined here; they MUST NOT invent per-service AuthZ error formats when using TokenSmith AuthZ middleware.

## 2. Definitions

- **AuthN**: Authentication (verifying the caller identity using TokenSmith JWT validation, including signature, issuer, audience, time claims, and required TokenSmith claims).
- **AuthZ**: Authorization (verifying the caller may perform an action on an object).
- **Principal**: The verified caller identity derived from an authenticated request.
- **Object**: A server-defined resource identifier (not user-supplied).
- **Action**: A server-defined operation identifier (not user-supplied).
- **Policy**: The effective authorization rules loaded into the Casbin enforcer.

## 3. Authorization modes

TokenSmith AuthZ MUST support the following modes:

- `off`: Authorization is disabled.
- `shadow`: Authorization is evaluated, but denials do not block the request.
- `enforce`: Authorization is evaluated and denials block the request.

Services MUST make the mode configurable (e.g., env var / config) and SHOULD expose the current mode via logs/metrics.

## 4. Decision taxonomy

The core authorization evaluator MUST return one of:

- `allow`: The policy permits the request.
- `deny`: The policy explicitly does not permit the request.
- `indeterminate`: A decision could not be made (e.g., missing required identity attributes, missing mapping information).
- `error`: An unexpected runtime error occurred during evaluation (e.g., Casbin error).

### 4.1 Mapping decisions to HTTP behavior

- In **enforce** mode:
  - `allow` MUST allow the request to proceed.
  - `deny`, `indeterminate`, and `error` MUST deny the request with **HTTP 403**.
- In **shadow** mode:
  - `allow` MUST allow the request to proceed.
  - `deny` MUST allow the request to proceed but MUST emit an AuthZ metric/log indicating a shadow denial.
  - `indeterminate` and `error` MUST allow the request to proceed but MUST emit an AuthZ metric/log indicating indeterminate/error with the reason.
- In **off** mode:
  - The request MUST proceed without authorization evaluation.

## 5. Failure behavior

### 5.1 Startup policy load/parse failures (all modes)

If the policy model and/or policy data fails to load or parse at startup, TokenSmith AuthZ MUST **fail fast**:

- The process MUST exit non-zero.

Rationale: prevents accidental allow-all due to missing or invalid policy.

### 5.2 Runtime evaluation failures

- In **enforce** mode, a runtime evaluation error (including Casbin errors) MUST:
  - deny the request by default, and
  - return **HTTP 403** with the stable TokenSmith AuthZ error body (see §6).

- In **shadow** mode, a runtime evaluation error MUST:
  - allow the request, and
  - emit an AuthZ metric/log with decision `error` (or `indeterminate`) and a reason.

## 6. Error body strategy (stable JSON schema)

When TokenSmith AuthZ middleware denies a request (enforce mode), it MUST return a JSON error object using this schema:

```json
{
  "code": "AUTHZ_DENIED",
  "message": "access denied",
  "request_id": "<optional>",
  "policy_version": "<policy hash>",
  "decision": "deny"
}
```

Normative requirements:

- `code` MUST be a stable, machine-readable string owned by TokenSmith.
- `message` MUST be a human-readable summary. It MUST be stable enough for operators but MUST NOT contain sensitive policy internals.
- `request_id` MUST be included when a request id is present in the request context (see §6.1).
- `policy_version` MUST be present and MUST equal the deterministic policy hash of the effective policy set (see §9).
- `decision` MUST be one of `deny`, `indeterminate`, or `error` (for enforced denials).

### 6.1 Request ID sourcing

If a request id is available in context, TokenSmith SHOULD propagate it in `request_id`.

TokenSmith AuthZ MUST NOT require per-service hooks to extract request ids. It MUST use a built-in strategy (e.g., context key and/or common headers) that is documented and consistent.

## 7. Route protection model

When TokenSmith AuthZ middleware is installed in a service:

- Authorization MUST be **deny-by-default**.
- Services MUST explicitly mark routes that are unauthenticated or unprotected as `Public` / `SkipAuthz` (exact API described by TokenSmith).

Services MUST derive `object` and `action` from **route registration** and/or server constants.

Services MUST NOT accept `object` and/or `action` as user input.

## 8. Identity / claims mapping

### 8.1 Authentication prerequisite

TokenSmith assumes TokenSmith JWT validation is performed:

- by TokenSmith AuthN middleware (preferred), OR
- by an upstream middleware that populates an equivalent **verified principal** in request context using TokenSmith-defined types/keys.

Services MUST NOT run TokenSmith AuthZ on an unverified identity.

### 8.2 Principal types

TokenSmith MUST distinguish between two principal types:

- `user`
- `service`

#### User principal requirements

A `user` principal requires:

- `sub` (user id), AND
- either `roles[]` OR `groups[]`.

#### Service principal requirements

A `service` principal requires one of:

- `azp` (authorized party), OR
- `client_id`.

A service principal MUST be mapped to role `service` (either directly via `roles[]` or indirectly via `groups[]`/mappings).

### 8.3 Role resolution rules

Roles are additive.

If multiple roles are present, authorization MUST be satisfied if **ANY** role grants `(subject, object, action)`.

## 9. Policy version identity (deterministic hash)

TokenSmith MUST compute a deterministic policy hash over the fully loaded **effective policy set**.

- The hash MUST change when the effective policy changes.
- The hash MUST be exposed via:
  - logs and metrics, and
  - a Go function callable by services.

## 10. RBAC role model (minimum required roles)

TokenSmith MUST support, at minimum, the following roles:

- `admin`: full CRUD on all resources across all services
- `operator`: read and write boot configs, metadata, and SMD state; **no delete**
- `viewer`: read-only access to all resources
- `service`: service-to-service calls (e.g., boot-service reading metadata)

## 11. Examples (subject, object, action)

These examples illustrate how roles are expected to map to permissions. Exact `object`/`action` constants are service-defined.

- `admin`:
  - allow: `("role:admin", "boot:configs", "create")`
  - allow: `("role:admin", "metadata:nodes", "delete")`

- `operator`:
  - allow: `("role:operator", "boot:parameters", "update")`
  - deny: `("role:operator", "metadata:nodes", "delete")`

- `viewer`:
  - allow: `("role:viewer", "metadata:groups", "read")`
  - deny: `("role:viewer", "boot:configs", "update")`

- `service`:
  - allow: `("role:service", "metadata:nodes", "read")`
  - deny: `("role:service", "boot:configs", "delete")`

## 12. Integration checklist (services)

Services integrating TokenSmith AuthZ MUST:

1. Perform AuthN with TokenSmith JWT middleware (or provide a verified principal in context using TokenSmith types).
2. Configure AuthZ mode: `off` | `shadow` | `enforce`.
3. Load policy model + policy data at startup; allow TokenSmith to fail fast on errors.
4. Install TokenSmith AuthZ middleware with deny-by-default behavior.
5. Mark any public/unprotected endpoints as `Public` / `SkipAuthz`.
6. Define server constants for `object` and `action` per route (not user input).
7. Ensure roles/groups claims are present for users; ensure service tokens map to role `service`.
8. Emit or propagate request ids consistently so TokenSmith can return `request_id` in error bodies.
9. Surface `policy_version` in logs/metrics for operational debugging.
