<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Exported symbols baseline

This document tracks key exported APIs for current TokenSmith authn/authz integrations.

## Package pkg/authn

- Types and options:
  - `type Mode`
  - `type PrincipalMapper`
  - `type Options`
- Middleware and helpers:
  - `Middleware(opt Options) (func(http.Handler) http.Handler, error)`
  - `ContextWithPrincipal(ctx context.Context, p authz.Principal) context.Context`
  - `PrincipalFromContext(ctx context.Context) (authz.Principal, bool)`
  - `ContextWithVerifiedClaims(ctx context.Context, c map[string]any) context.Context`
  - `VerifiedClaimsFromContext(ctx context.Context) (map[string]any, bool)`

## Package pkg/authz

- Core types/constants:
  - `type Mode`
  - `type Decision`
  - `type ErrorCode`
  - `type ErrorResponse`
  - `type Principal`
  - `type AuthzResult`
- Authorizer API:
  - `NewAuthorizer(...)`
  - `WithDecisionCache(...)`
  - `WithDecisionCacheFromEnv()`
  - `(*Authorizer) Authorize(...)`
  - `(*Authorizer) PolicyVersion()`

## Package pkg/authz/policyloader

- Constants:
  - `EnvPolicyDir`
  - `EnvPolicyDirCompat`
- Loader API:
  - `New()`
  - `(*Loader) LoadFromEnv()`
  - `(*Loader) Load(policyDir string)`
  - `(*Loader) PolicyVersion()`

## Package pkg/authz/chi

- Context helpers:
  - `SetPrincipal(ctx context.Context, p *authz.Principal) context.Context`
  - `PrincipalFromContext(ctx context.Context) (*authz.Principal, bool)`
- Route annotations:
  - `Require(object, action string)`
  - `Public()`
  - `SkipAuthz()`
- Middleware:
  - `New(authorizer *authz.Authorizer, opts ...Option) *Middleware`
  - `(*Middleware) Handler(next http.Handler) http.Handler`
- Options and diagnostics:
  - `WithMode(...)`
  - `WithMetrics(...)`
  - `WithRequestIDFunc(...)`
  - `WithAllowMissingPrincipal(...)`
  - `WithPolicySource(...)`
  - `LogStartupDiagnostics(...)`

## Package pkg/oidc

- Middleware:
  - `RequireToken(next http.Handler) http.Handler`
  - `RequireValidToken(provider Provider) func(http.Handler) http.Handler`
- Context key types:
  - `TokenCtxKey{}`
  - `IntrospectionCtxKey{}`
