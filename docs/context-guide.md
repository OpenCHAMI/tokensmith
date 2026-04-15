<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith middleware and context guide

This guide defines the current TokenSmith middleware model and recommended wiring for services.

## Supported middleware model

Use TokenSmith with this split of responsibilities:

- authentication and TokenSmith JWT verification: `pkg/authn`
- authorization and policy decisions: `pkg/authz`

## Context model

TokenSmith standardizes on a normalized authorization identity:

- principal type: `authz.Principal`

Canonical helpers:

- `authz.SetPrincipal(ctx, p)`
- `authz.PrincipalFromContext(ctx)`
- `authn.PrincipalFromContext(ctx)`
- `authn.VerifiedClaimsFromContext(ctx)` for verified claims not represented in principal

When using `pkg/authn` middleware, no service-specific bridge is required:

- AuthN stores principal in authn context
- AuthN also stores principal in authz context

## Recommended middleware ordering

1. request ID / logging middleware
2. AuthN middleware (`pkg/authn`)
3. AuthZ middleware (`pkg/authz`)
4. application handler

## Working example

```go
mapper := authn.MapperFunc(func(ctx context.Context, claims *token.TSClaims) (authz.Principal, error) {
    return authz.Principal{
        ID:    claims.Subject,
        Type:  "service",
        Roles: []string{"service"},
    }, nil
})

r.Use(authn.Middleware(authn.Options{
    Issuer:   "https://tokensmith.example",
    Audience: []string{"metadata-service"},
    JWKSURLs: []string{"https://tokensmith.example/.well-known/jwks.json"},
    Mapper:   mapper,
}))

r.Use(authzMiddleware)

r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
    principal, ok := authz.PrincipalFromContext(r.Context())
    if !ok {
        http.Error(w, "missing principal", http.StatusUnauthorized)
        return
    }
    _, _ = w.Write([]byte(principal.ID))
})
```

## Failure expectations

If AuthZ runs without a principal present, treat the request as an authentication failure path and return a consistent service error response.

In practice:

- AuthN should reject malformed or unverifiable tokens before AuthZ runs
- if your handler reads principal directly, always handle the missing-principal case explicitly
- unmapped routes in enforce mode should be treated as deny-by-default according to your AuthZ configuration

## Adoption checklist

1. Configure `authn.Middleware(authn.Options{...})` with issuer, audience, and JWKS or static key material.
2. Provide an `authn.Mapper` that maps verified claims into `authz.Principal`.
3. Attach AuthZ middleware with a route mapper or path/method mapper.
4. Read principal in handlers with `authn.PrincipalFromContext` or `authz.PrincipalFromContext`.
5. Roll out authorization in `shadow` mode before moving to `enforce`.
6. Track `policy_version` during rollout to verify consistent policy deployment.

## Common wiring issues

| Issue | Outcome | Fix |
| --- | --- | --- |
| AuthZ before AuthN | Missing principal, request denied | Ensure AuthN runs before AuthZ |
| Missing required TokenSmith claims | AuthN rejection | Ensure the token includes the required TokenSmith claim set |
| Wrong JWKS URL | Signature validation fails | Configure `/.well-known/jwks.json` directly |
| Route not mapped in enforce mode | Deny-by-default response | Add explicit route mapping or public route annotation |
| Policy changed without restart | Old policy still active | Restart service (no hot reload in v1) |
