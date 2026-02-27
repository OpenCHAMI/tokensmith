<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Exported symbols to keep compatible (feature/ursa-authorizer baseline)

This is a *best-effort* compatibility inventory of exported packages/types/functions that exist on this branch and are likely used by downstream services.

If we must change behavior, prefer additive changes (new packages/options) and keep these symbols working.

## Package `middleware` (module root `/middleware`)

- Types/constants:
  - `type ContextKey string`
  - `const ClaimsContextKey ContextKey`
  - `const RawClaimsContextKey ContextKey`
  - `type MiddlewareOptions struct { ... }`
- Functions:
  - `DefaultMiddlewareOptions() *MiddlewareOptions`
  - `JWTMiddleware(key any, opts *MiddlewareOptions) func(http.Handler) http.Handler`
  - `GetClaimsFromContext(ctx context.Context) (*token.TSClaims, error)`
  - `GetRawClaimsFromContext(ctx context.Context) (*token.TSClaims, error)`
  - `RequireScope(requiredScope string) func(http.Handler) http.Handler`
  - `RequireScopes(requiredScopes []string) func(http.Handler) http.Handler`
  - `RequireServiceToken(requiredService string) func(http.Handler) http.Handler`

## Package `pkg/authz`

- Types/constants:
  - `type Mode string` (`off|shadow|enforce`)
  - `type Decision string` (`allow|deny|indeterminate|error`)
  - `type ErrorCode string` (`AUTHZ_DENIED|AUTHZ_INDETERMINATE|AUTHZ_ERROR`)
  - `type ErrorResponse struct { Code, Message, RequestID, PolicyVersion, Decision }`
  - `type Principal struct { ID string; Roles []string }`
  - `type AuthzResult struct { PolicyVersion, MatchedRoles, Reason, Cached }`
  - `type Authorizer struct { ... }`
- Functions/options:
  - `NewAuthorizer(enforcer *casbin.Enforcer, policyVersion string, opts ...AuthorizerOption) (*Authorizer, error)`
  - `WithDecisionCache(size int) AuthorizerOption`
  - `WithDecisionCacheFromEnv() AuthorizerOption`
  - `(*Authorizer) Authorize(ctx context.Context, principal Principal, object, action string) (Decision, *AuthzResult)`
  - `(*Authorizer) PolicyVersion() string`

## Package `pkg/authz/policyloader`

- Constants:
  - `EnvPolicyDir = "TOKENS_MITH_POLICY_DIR"`
  - `EnvPolicyDirCompat = "AUTHZ_POLICY_DIR"`
- Types:
  - `type Loader struct { ... }`
- Functions:
  - `New() *Loader`
  - `(*Loader) LoadFromEnv() (*casbin.Enforcer, error)`
  - `(*Loader) Load(policyDir string) (*casbin.Enforcer, error)`
  - `(*Loader) PolicyVersion() string`

## Package `pkg/authz/chi`

- Context helpers:
  - `SetPrincipal(ctx context.Context, p *authz.Principal) context.Context`
  - `PrincipalFromContext(ctx context.Context) (*authz.Principal, bool)`
- Route annotations:
  - `Require(object, action string) func(http.Handler) http.Handler`
  - `Public() func(http.Handler) http.Handler`
  - `SkipAuthz() func(http.Handler) http.Handler`
- Middleware:
  - `type Middleware struct { ... }`
  - `New(authorizer *authz.Authorizer, opts ...Option) *Middleware`
  - `(*Middleware) Handler(next http.Handler) http.Handler`
- Options:
  - `WithMode(mode authz.Mode) Option`
  - `WithMetrics(metrics Metrics) Option`
  - `WithRequestIDFunc(f func(context.Context) string) Option`
  - `WithAllowMissingPrincipal(allow bool) Option`
  - `WithPolicySource(source PolicySource) Option`
- Diagnostics:
  - `LogStartupDiagnostics(mode string, policyVersion string, source PolicySource)`

## Package `pkg/oidc`

- Middleware:
  - `RequireToken(next http.Handler) http.Handler`
  - `RequireValidToken(provider Provider) func(http.Handler) http.Handler`
- Context keys (types):
  - `TokenCtxKey{}`
  - `IntrospectionCtxKey{}`
