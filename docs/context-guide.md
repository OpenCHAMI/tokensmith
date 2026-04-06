<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith middleware and context guide

This guide defines the current TokenSmith middleware model and recommended wiring for services.

## Supported middleware model

Use TokenSmith with this split of responsibilities:

- Authentication and TokenSmith JWT verification: `pkg/authn`
- Authorization and policy decisions: `pkg/authz`

## Context model

TokenSmith standardizes on a normalized authorization identity:

- Principal: `authz.Principal`

Canonical helpers:

- `authz.SetPrincipal(ctx, p)`
- `authz.PrincipalFromContext(ctx)`
- `authn.PrincipalFromContext(ctx)`

When using `pkg/authn` middleware, no service-specific bridge is required:

- AuthN stores principal in `authn` context (`authn.PrincipalFromContext`)
- AuthN also stores principal in `authz` context (`authz.PrincipalFromContext`)

Use verified claims only when needed for fields not represented by principal:

- `authn.VerifiedClaimsFromContext(ctx)`

## Middleware ordering

Recommended order:

1. request-id middleware (optional)
2. AuthN middleware (`pkg/authn`) to verify TokenSmith JWTs and set principal
3. AuthZ middleware (`pkg/authz`) to enforce policy
4. application handler

## Failure expectations

If AuthZ runs without a principal present, treat the request as an authentication failure path and return a consistent error response according to your service policy and `docs/authz-spec.md`.

## Adoption checklist

1. Configure `authn.Middleware(authn.Options{...})` with issuer, audience, and key material for TokenSmith JWTs.
2. Provide an `authn.Mapper` that maps verified claims into `authz.Principal`.
3. Attach `authz` middleware with a route mapper or path/method mapper.
4. Read principal in handlers with `authn.PrincipalFromContext` or `authz.PrincipalFromContext`.
5. Roll out authorization in `shadow` mode before moving to `enforce`.
6. Track `policy_version` during rollout to verify consistent policy deployment.

## Common wiring issues

| Issue | Outcome | Fix |
| --- | --- | --- |
| AuthZ before AuthN | Missing principal, request denied | Ensure AuthN runs before AuthZ |
| Missing required TokenSmith claims | AuthN rejection | Ensure the token includes the required TokenSmith claim set |
| Route not mapped in enforce mode | Deny-by-default response | Add explicit route mapping or public route annotation |
| Policy changed without restart | Old policy still active | Restart service (no hot reload in v1) |
