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
- `authn.HumanSessionClaimsFromContext(ctx)` for defensive-copy typed human claims and exact int64 IDs

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
mapper := authn.PrincipalMapper(func(ctx context.Context, parsed *jwt.Token, claims jwt.MapClaims) (authz.Principal, error) {
    subject, _ := claims["sub"].(string)
    return authz.Principal{
        ID:    subject,
        Roles: []string{"service"},
    }, nil
})

authenticate, err := authn.Middleware(authn.Options{
    Issuers:   []string{"https://tokensmith.example"},
    Audiences: []string{"metadata-service"},
    JWKSURLs: []string{"https://tokensmith.example/.well-known/jwks.json"},
    Mapper:   mapper,
})
if err != nil {
    return err // During service startup, before accepting requests.
}
r.Use(authenticate)

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

This mapper is legacy-only and assigns a service-owned role after verification.
For human or mixed consumers, use the explicit policy/profile configuration in
[token-profiles.md](token-profiles.md) and its complete compiled example. Human
roles come from signed claims, not this mapper. Import `jwt` from
`github.com/golang-jwt/jwt/v5`. The generic AuthZ context used here is distinct
from `authz/chi`'s context; do not assume an automatic bridge to that package.

## Failure expectations

If AuthZ runs without a principal present, treat the request as an authentication failure path and return a consistent service error response.

In practice:

- AuthN should reject malformed or unverifiable tokens before AuthZ runs
- if your handler reads principal directly, always handle the missing-principal case explicitly
- unmapped routes in enforce mode should be treated as deny-by-default according to your AuthZ configuration

## Revocation enforcement

`pkg/authn` can reject revoked TokenSmith JWTs when the service supplies an
`authn.RevocationChecker`:

```go
authnMiddleware, err := authn.Middleware(authn.Options{
    Issuers:           []string{"https://tokensmith.example"},
    Audiences:         []string{"metadata-service"},
    JWKSURLs:          []string{"https://tokensmith.example/.well-known/jwks.json"},
    RevocationChecker: tokenService,
    Mapper:            mapper,
})
```

`TokenService` implements `IsRevoked(jti string) bool` for this purpose. The
store is process-local and in-memory: revocations are lost on restart and are not
propagated to other services or replicas. Consumers that need cross-process
revocation must provide their own shared checker implementation. Tokens without
a `jti` are not checked or stored as revoked.

Legacy validation still enforces the TokenSmith/NIST claim set when
called with `enforce=true`; human sessions use their own strict bounded policy,
not fabricated MFA/assurance. The optional JTI check runs for both profiles; it
does not make logout a distributed/session-wide JWT revocation mechanism.
Provider-specific exchange paths, such as Vault mode,
must populate safe generated values before minting a TokenSmith JWT instead of
globally disabling claim enforcement.

## Adoption checklist

1. Configure `authn.Middleware(authn.Options{...})` with issuer, audience, and JWKS or static key material.
2. For legacy claims, optionally provide an `authn.PrincipalMapper`; for human sessions explicitly enable the profile and policy.
3. Attach an `authn.RevocationChecker` when the service has a revocation source.
4. Attach AuthZ middleware with a route mapper or path/method mapper.
5. Read principal in handlers with `authn.PrincipalFromContext` or `authz.PrincipalFromContext`.
6. Roll out authorization in `shadow` mode before moving to `enforce`.
7. Track `policy_version` during rollout to verify consistent policy deployment.

## Common wiring issues

| Issue | Outcome | Fix |
| --- | --- | --- |
| AuthZ before AuthN | Missing principal, request denied | Ensure AuthN runs before AuthZ |
| Missing required TokenSmith claims | AuthN rejection | Ensure the token includes the required TokenSmith claim set |
| Wrong JWKS URL | Signature validation fails | Configure `/.well-known/jwks.json` directly |
| Route not mapped in enforce mode | Deny-by-default response | Add explicit route mapping or public route annotation |
| Policy changed without restart | Old policy still active | Restart service (no hot reload in v1) |
