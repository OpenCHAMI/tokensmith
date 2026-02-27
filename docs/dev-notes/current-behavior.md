<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith (feature/ursa-authorizer) – current behavior audit (legacy)

This note inventories the current branch state before we evolve TokenSmith into a more general, Casbin-first authn/authz library.

Goals of this audit:

- Avoid regressions for existing users in this branch.
- Identify exported APIs/types that are already relied upon.
- Capture HTTP status/response behavior and middleware ordering expectations.
- Verify logging does not leak JWTs or sensitive claims.

## Repository shape / key packages

### `middleware/` (legacy JWT + optional Casbin check)

- Primary entrypoint: `middleware.JWTMiddleware(key any, opts *MiddlewareOptions) func(http.Handler) http.Handler`
- Context keys:
  - `middleware.ClaimsContextKey` (`ContextKey("jwt_claims")`)
  - `middleware.RawClaimsContextKey` (`ContextKey("jwt_raw_claims")`)
- Helpers:
  - `middleware.GetClaimsFromContext(ctx)` -> `(*token.TSClaims, error)`
  - `middleware.GetRawClaimsFromContext(ctx)` -> `(*token.TSClaims, error)` (note: despite name, returns `*token.TSClaims`)
  - `middleware.RequireScope(scope)` / `middleware.RequireScopes([]string)`
  - `middleware.RequireServiceToken(requiredService string)`

Notes:

- This package is **net/http compatible**.
- It supports:
  - static key verification OR JWKS (`opts.JWKSURL`) with background refresh.
  - expiration validation via `claims.Validate(!opts.NonEnforcing)`.
  - required claims checks for `sub`, `iss`, `aud`.
- It also contains an *optional* inline Casbin authorization check when both:
  - `opts.PolicyModelFile != ""` AND
  - `opts.PolicyPermissionsFile != ""`
  This logic creates a new `casbin.Enforcer` **per request** and iterates over `aud` x `scope` pairs.

HTTP behavior (legacy):

- Missing `Authorization` header:
  - if `AllowEmptyToken`: request proceeds.
  - else: `401` with plaintext body `missing authorization header`.
- Invalid `Authorization` header format: `401` `invalid authorization header format`.
- Invalid token / parse error: `401` `invalid token: <err>` (includes error string).
- Validation failures (exp etc): `401` `token validation failed: <err>`.
- Scope middleware denies: `401 insufficient scope`.
- `RequireServiceToken`:
  - missing raw claims: `401 invalid token type`
  - invalid target service: `403 invalid target service`
  - missing service ID: `401 missing service ID`

Logging (legacy):

- Uses `zerolog/log`.
- Only visible log in `middleware.JWTMiddleware` is:
  - `log.Debug().Msgf("found valid permissions for subject '%s'", sub)`
- The code does **not** log the raw JWT token string.
- The legacy middleware does sometimes include error strings in HTTP responses; those errors *can* contain claim values depending on jwt library error formatting.

Compatibility constraints:

- Keep `middleware/` package exported API stable for existing consumers.
- Preserve context keys and claim access helpers.

### `pkg/authz` (Casbin-first authorizer contract)

This branch already includes a newer, Casbin-first authorization subsystem used by chi middleware.

Key exported types/APIs:

- `pkg/authz`:
  - `type Mode string` with constants: `off`, `shadow`, `enforce`
  - `type Decision string` with constants: `allow`, `deny`, `indeterminate`, `error`
  - `type Principal struct { ID string; Roles []string }`
  - `type ErrorResponse struct { code, message, request_id?, policy_version, decision }`
  - `type Authorizer` with:
    - `NewAuthorizer(enforcer *casbin.Enforcer, policyVersion string, opts ...AuthorizerOption)`
    - `Authorize(ctx, principal, object, action) (Decision, *AuthzResult)`
    - optional decision LRU cache (`WithDecisionCache`, `WithDecisionCacheFromEnv`)

Behavior:

- The authorizer treats roles as the Casbin subject via `sub := "role:" + role`.
- Decision evaluation is: allow if **any** role allows `(obj, act)`.
- If principal ID missing / roles missing / object/action missing -> `DecisionIndeterminate`.

Compatibility constraints:

- Keep role prefix behavior (`role:`) stable.
- Keep `PolicyVersion()` and decision taxonomy stable.

### `pkg/authz/policyloader` (baseline policy + fragment loader)

- Loads embedded baseline model (`baseline_model.conf`) + baseline policy (`baseline_policy.csv`).
- Optional fragments loaded from a directory:
  - env: `TOKENS_MITH_POLICY_DIR` (preferred) or `AUTHZ_POLICY_DIR` (compat).
  - load order: lexical order by filename.
  - accepts `*.csv` or `*.policy.csv`.
- Computes `policy_version` as sha256 over:
  - normalized model text
  - normalized effective policy lines (baseline + fragments)

Compatibility constraints:

- Preserve env var names.
- Preserve deterministic lexical ordering and hash computation.

### `pkg/authz/chi` (chi-specific authz middleware)

Exported API:

- Context utilities:
  - `SetPrincipal(ctx, *authz.Principal) context.Context`
  - `PrincipalFromContext(ctx) (*authz.Principal, bool)`
- Route annotations:
  - `Require(object, action string) func(http.Handler) http.Handler`
  - `Public()` / `SkipAuthz()`
- Middleware:
  - `New(authorizer, ...Option) *Middleware`
  - `(*Middleware).Handler(next) http.Handler`
- Options:
  - `WithMode(authz.Mode)`
  - `WithAllowMissingPrincipal(bool)`
  - `WithMetrics(Metrics)`
  - `WithRequestIDFunc(func(ctx) string)`
  - `WithPolicySource(PolicySource)`

Middleware ordering expectation:

- Documented inline: `request-id (optional) -> authn (JWT validation) -> authz`.
- Default behavior when requirement is present but principal is missing:
  - returns `401` plaintext `missing principal` unless `WithAllowMissingPrincipal(true)` is set.

Deny-by-default behavior:

- If middleware installed and route is not `SkipAuthz/Public` and does not set `Require(...)`:
  - the middleware denies (in enforce mode) with `403` JSON body (`authz.ErrorResponse`).

Modes:

- `off`: no evaluation, no denial.
- `shadow`: evaluates + metrics, but always allows.
- `enforce`: denies on non-allow decision.

Deny response schema (current):

- `403` `application/json` body:
  - `{code, message, request_id?, policy_version, decision}`
- Note: missing principal default (401) is not JSON.

Logging/metrics:

- Middleware itself does not log decisions (metrics interface exists).
- Startup log helper exists: `LogStartupDiagnostics(mode, policyVersion, source)` (uses stdlib log.Printf).

Compatibility constraints:

- Keep deny response schema stable.
- Keep deny-by-default semantics.
- Keep `Public/SkipAuthz` semantics.

## Existing tests that define behavior

- `pkg/authz/chi/golden_error_response_test.go`
  - validates JSON schema keys exist.
- `pkg/authz/chi/golden_metrics_labels_test.go`
  - validates metrics label contract.
- `pkg/authz/chi/e2e_middleware_flow_test.go`
  - validates ordering/flow with chi.
- `pkg/authz/policyloader/policyloader_test.go`
  - validates fragment discovery, ordering, hash stability.

## Backward-compatibility checklist (must not break)

1. `middleware/` package:
   - exported `MiddlewareOptions`, `DefaultMiddlewareOptions`, `JWTMiddleware`, context keys, and helper functions.
   - behavior and status codes should not change unexpectedly for existing callers.
2. `pkg/authz` and `pkg/authz/chi` exported APIs and existing deny JSON schema.
3. Policy loader env vars and fragment ordering/hash stability.

## Known gaps vs desired future direction

- Legacy `middleware/JWTMiddleware` mixes AuthN and (optional) AuthZ and creates a new enforcer per request.
- No net/http AuthZ middleware (non-chi) exists yet; current implementation is chi-only.
- No path/method Casbin-native style support yet.
- No principal type (user/service), domain support, or richer error reasons yet.
- Decision logging is minimal.
