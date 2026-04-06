<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith current behavior audit

This note captures the current middleware and authorization behavior in the repository.

## Middleware architecture

- AuthN: `pkg/authn` verifies JWTs, validates issuer/audience/time constraints, and maps verified claims into `authz.Principal`.
- AuthZ: `pkg/authz` evaluates policy decisions and exposes middleware integrations (`pkg/authz/chi`).
- Policy loading: `pkg/authz/policyloader` builds effective model and policy from embedded baseline plus optional filesystem fragments.

## Request processing model

Recommended stack order:

1. Request ID and transport middleware
2. AuthN middleware (`pkg/authn`)
3. AuthZ middleware (`pkg/authz` integration)
4. Route handler

## AuthN behavior summary

`pkg/authn`:

- Enforces FIPS-approved JWT methods.
- Supports static key verification and JWKS-based key discovery.
- Applies explicit clock skew and required time claims.
- Performs issuer and audience checks when enabled.
- Stores principal and verified claims in request context.
- Emits structured auth failure logs with reason codes.

## AuthZ behavior summary

`pkg/authz`:

- Uses decision taxonomy: allow, deny, indeterminate, error.
- Supports rollout modes: off, shadow, enforce.
- Provides deny-by-default behavior for unmapped routes in enforce mode.
- Returns stable JSON error schema for policy denials.

## Operational invariants

- Policies are loaded at startup.
- No policy hot reload in v1.
- `policy_version` is deterministic from effective model and policy inputs.

## Validation anchors

Current behavior is validated by tests in:

- `pkg/authn/*_test.go`
- `pkg/authz/*_test.go`
- `pkg/authz/chi/*_test.go`
- `pkg/authz/policyloader/*_test.go`
