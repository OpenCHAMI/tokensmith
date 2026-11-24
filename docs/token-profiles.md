<!-- SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Token profiles and consumer migration

Use **`authn.Middleware(authn.Options{...})`** for HTTP authentication, followed
by service-owned `authz`/Casbin authorization. Device acquisition and renewal stay
in `deviceauth`; authoritative human claims and verification belong to `token`.
The complete, compiling wiring is in
[`examples/profiles/example_test.go`](../examples/profiles/example_test.go).

## Signed routing and defaults

`Options.Profiles` defaults to `[]token.Profile{token.ProfileLegacyV1}`. Merely
supplying `HumanSessionPolicy` does not enable human sessions. Select one or both
known, unique profiles explicitly. Each request selects one signed contract;
verification failure never retries a different profile.

| Signed payload | Legacy only (default) | Human only | Mixed |
| --- | --- | --- | --- |
| No marker, valid legacy claims | Accept | Reject | Accept |
| `token_profile: "legacy-v1"`, valid legacy claims | Accept | Reject | Accept |
| `token_profile: "human-session-v1"`, valid human claims | Reject | Accept | Accept |
| Unmarked old draft human token | Reject; reissue | Reject; reissue | Reject; reissue |
| Unknown/null/non-string/duplicate marker or conflicting claims | Reject | Reject | Reject |
| Enabled profile with bad signature, key, binding, role or lifetime | Reject | Reject | Reject |

To prevent marker stripping, legacy routing reserves `token_class=human` and the
presence of `gitlab_issuer`, `gitlab_project_id`, `gitlab_user_id`, `approved_at`,
or `membership_checked_at`, even when null. This is an intentional restriction on
legacy extensions. Duplicate fields and case aliases reject. Human tokens cannot
carry legacy assurance/identity extensions such as `auth_level` or `scope`.
Existing legitimate unmarked legacy tokens remain supported, including tokens
larger than 8192 bytes; HTTP/server header limits remain caller-owned. Human
verification retains its explicit 8192-byte cap.

## Consumer-only configuration and trust

```go
policy := token.HumanSessionPolicy{
    ClusterIssuer: "https://tokens.example.org", Audience: "nodes",
    GitLabIssuer: "https://gitlab.example.org", ProjectID: 123,
    CacheSeconds: 90, TokenSeconds: 180, SkewSeconds: 30, AbsoluteSeconds: 36000,
}
authenticate, err := authn.Middleware(authn.Options{
    Profiles: []token.Profile{token.ProfileHumanSessionV1},
    HumanSessionPolicy: &policy,
    Issuers: []string{policy.ClusterIssuer}, Audiences: []string{policy.Audience},
    JWKSURLs: []string{"https://tokens.example.org/.well-known/jwks.json"},
})
```

Handle the constructor error before serving. Human and mixed modes require
issuer/audience validation enabled and exactly one configured issuer and audience
matching the policy. Legacy-only multiissuer behavior is unchanged. Policies and
configuration slices are snapshotted. `Config.ConsumerPolicy()` projects broker
configuration without client IDs, verifier paths, credentials or role mappings;
consumers can construct the secret-free policy independently.

Use configured `StaticKeys` (thumbprint key IDs) or `JWKSURLs` for keys trusted for
that fixed cluster issuer, never token-supplied issuer/`jku`/URLs. Maintain bounded
clock error and cache/rotation policy. The narrow `HumanSessionKeyLookup` callback
supports existing named-RSA-key integrations; it is authoritative for humans:
errors, unknown IDs, nil keys or invalid keys **never fall back** to static/JWKS
keys. It must resolve only that policy's trusted issuer. It cannot relax legacy
key requirements. No new key cache or dynamic trust discovery is introduced.

## Claims, principal and authorization

`Mapper` (`authn.PrincipalMapper`) applies only to legacy claims. Human principal
ID and role come directly from the verified subject and signed role. Both profiles
populate `authn.PrincipalFromContext` and the generic `authz.PrincipalFromContext`.
Generic `authz.NewMiddleware` consumes that context; `authz/chi` has a separate
principal context and needs explicit service wiring, not an assumed bridge.

Use `authn.HumanSessionClaimsFromContext(ctx)` for exact int64 project/user IDs,
including above 2^53. It returns a defensive copy, including the audience slice.
`VerifiedClaimsFromContext` preserves the old legacy map shape; the optional human
compatibility map uses `json.Number`, not float64. Do not derive authoritative
human identity from a lossy map. Roles are authorization roles, **not scopes**;
the service's Casbin model and route policy still decide read/write permissions.

Approval is not authentication time or evidence of MFA. Assurance not established
by this flow stays unknown; do not manufacture `amr`, `acr`, or authentication
factor claims. Legacy assurance validation is unchanged. The session contracts
are intentionally different: legacy requires `session_exp <= exp`; humans require
`exp + skew <= session_exp` against the fixed ten-hour deadline. Human
expiry is strict even with generic `ClockSkew` configured. Membership cache +
token life + total clock error is bounded by 300 seconds.

An optional `RevocationChecker` checks verified JTIs for both profiles before
context installation. The built-in TokenService checker is process-local and
in-memory, not distributed or session-wide revocation; external consumers need
their own shared checker for such guarantees. Logout denies renewal but already
issued JWTs remain valid only until their bounded short expiry. Human JTIs are
required; legacy tokens without a JTI retain existing optional-check semantics.

## Migration and operations

`deviceauth.Middleware` is a deprecated human-only forwarding wrapper; use the
common AuthN interface for new and migrated consumers. Direct helper signatures,
typed `Claims` alias and `errors.Is(err, deviceauth.ErrDenied)` remain available.
HTTP failures use the common sanitized `invalid token` body, 401, `no-store`, and
Bearer challenge; duplicate Authorization headers reject. Reissue old unmarked
human drafts rather than enabling an implicit fallback.

This does not redesign signing, JWKS publication or rotation. There is no live
rotation API, HA session store or persisted renewal state; restart requires fresh
approval and maintenance must coordinate consumer key caches. See
[GitLab device authorization](gitlab-device-auth.md) for broker provisioning and
[the context guide](context-guide.md) for legacy mapping and middleware order.
