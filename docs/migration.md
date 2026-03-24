<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith migration guide (context keys, ordering, rollout)

TokenSmith is evolving into the canonical owner of OpenCHAMI AuthN/AuthZ standards.

This document defines **compatibility guardrails** so existing services keep working while
new middleware and a more explicit principal model are rolled out.

## Context keys: legacy vs new

### Legacy (existing)

The legacy JWT middleware (`github.com/openchami/tokensmith/middleware`) stores validated JWT claims into request context:

- `middleware.ClaimsContextKey` (value: `*token.TSClaims`)
- `middleware.RawClaimsContextKey` (value: `*token.TSClaims`)

Accessors:

- `middleware.GetClaimsFromContext(ctx)`
- `middleware.GetRawClaimsFromContext(ctx)`

These APIs remain for compatibility.

### New (recommended)

TokenSmith standardizes on storing a normalized authorization identity:

- **Principal**: `*authz.Principal`

Canonical helpers:

- `tokensmith.SetPrincipal(ctx, p)`
- `tokensmith.PrincipalFromContext(ctx)`

## Compatibility strategy

For at least one release line:

- **Read-old + read-new**: `tokensmith.PrincipalFromContext(ctx)` reads:
  1) the new principal key (if present)
  2) else, derives a minimal principal from legacy JWT claims (if present)

- **Write-new only** (recommended): new AuthN middleware should store principals via `tokensmith.SetPrincipal`.
  - Services may optionally continue storing legacy claims for downstream code during migration.

### Legacy principal derivation

When only legacy JWT claims exist, `tokensmith.PrincipalFromContext` derives:

- `principal.ID = claims.Subject`
- `principal.Roles = claims.Scope`

This is best-effort to preserve behavior for services that previously used `scope` as an authorization input.

## Middleware ordering expectations

AuthZ expects AuthN to run before it.

Recommended order:

1) request-id middleware (optional)
2) AuthN middleware (JWT/OIDC validation; sets principal)
3) AuthZ middleware (Casbin enforcement)
4) application handler

### What if AuthZ runs without AuthN?

If AuthZ runs and no principal is present:

- strict configurations should treat it as an **AuthN failure** (`401`)
- compatibility configurations may return an **AuthZ denial** (`403`) with a stable JSON body

See `docs/authz-spec.md` for the normative wire contract.

## Practical adoption checklist

Use this sequence to migrate an existing service with minimal risk.

1. Keep existing AuthN in place.
2. Start writing principals with `tokensmith.SetPrincipal(ctx, p)` in AuthN.
3. Update authorization call-sites to read `tokensmith.PrincipalFromContext(ctx)`.
4. Keep legacy claims reads only where still required by older handlers.
5. Run in AuthZ `shadow` mode first and review decision logs/metrics.
6. Move to `enforce` after policy and principal shape are validated.

## Middleware ordering failure modes

| Ordering issue | Typical outcome | Recommended fix |
| --- | --- | --- |
| AuthZ before AuthN | Missing principal; request may fail as `401` or compatibility `403` depending on configuration | Ensure AuthN middleware runs before AuthZ |
| AuthN runs but does not set principal | AuthZ cannot evaluate intended subject/roles | Map verified JWT claims to `authz.Principal` and store with `tokensmith.SetPrincipal` |
| Route not mapped and not public in enforce mode | Deny-by-default `403` | Add explicit mapping or mark route public by policy/design |
| Policy changed without restart | Old policy still active | Restart service (no hot reload in v1) |

## What to remove last

Do not remove legacy `middleware.GetClaimsFromContext` usage until:

- all authorization decision paths read principals,
- downstream handlers no longer rely on direct legacy claim structs,
- shadow-mode observations show no unexpected denials.

## Deprecations

The following legacy helpers remain but are deprecated for new consumers:

- `middleware.GetClaimsFromContext`
- `middleware.GetRawClaimsFromContext`

They will be removed only after a documented deprecation period.
