<!-- SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC -->
<!-- SPDX-License-Identifier: MIT -->

# GitLab device authorization

`pkg/deviceauth` verifies GitLab identity and effective project membership using
[the shared device-grant transport](device-authorization.md). GitLab application
and project policy are separate from the reusable OAuth exchange.

## Provider support

GitLab is the only implemented device-authorization identity/membership adapter.
GitHub, Entra and Google profiles in `pkg/deviceflow` are **transport-only login
stubs**: their grant exchange is fixture-tested, but their identity verification,
permission mapping and device-login/session integration are not implemented.
Each needs a separate adapter and explicit cluster-role policy before enabling
login; a missing adapter or mapping must never imply administrator access.

The existing `/oauth/exchange` endpoint uses separate OIDC validation and
claim/scope policy. This adapter's membership checks do not apply to that path.

## Identity and permission checks

The provider answers two separate questions:

1. Which active GitLab user approved this OAuth application? A `read_user`
   credential checks the application and immutable user ID.
2. What can that user do in the configured project? A separate, private verifier
   credential reads `/members/all/ID`, including inherited membership.

The server configuration selects the HTTPS origin, application and project.
Requests cannot select those values or their own role. Redirects are refused;
errors never copy GitLab response bodies, URLs or credentials.

The membership cache window must be positive (1–90 seconds); zero is rejected
at configuration time because it leaves no time to complete a membership lookup.
The configuration reserves at most 90 seconds of membership cache, 180 seconds
of cluster-token life and 30 seconds of total clock error. Their sum cannot
exceed five minutes. Session approval lasts exactly ten hours; renewal cannot
move that deadline. These constraints bound the lifetime of session approval and
cached authority.

Tests use a local HTTPS GitLab fixture, including redirects, wrong applications,
wrong users, blocked accounts, expired tokens and membership lookup failures.
No GitLab account, cluster access or secrets are required.

## Session lifecycle

The session authority implements the login lifecycle:

1. `Start` keeps the private device code and returns a random transaction handle.
2. `Poll` consumes approval once, verifies identity and membership, then fixes the
   absolute deadline. By default Owner/Maintainer maps to admin, Developer to
   operator and Reporter to viewer; Guest/nonmember is denied. An optional
   `gitlab_role_mapping` can replace these assignments.
3. `Renew` verifies the same user again, refreshes GitLab credentials when needed
   and rechecks membership within the cache budget. It cannot move the deadline.
4. `Logout` removes renewal state before contacting GitLab to revoke access.

`tokens.go` signs and verifies the resulting user-session claim contract. Token
expiry is strict: the reserved clock budget is not added again as expiry leeway.
Each token expires at the earliest permitted token, upstream or session limit.
Consumers still need issuer-bound keys, bounded clocks and route authorization.
A signed role is useful only when the consumer enforces it.

A short map mutex protects bounded state; separate cancellable gates serialize
each transaction and each session’s credential rotation and logout. Upstream
calls never hold the map mutex, so slow calls do not block unrelated sessions.
Logout waits for an in-flight renewal of the same session before revoking its
latest credential. Provider, signer and audit implementations must support
concurrent calls. Audit callbacks run after all authority locks are released.
State is memory-only; restart requires fresh approval.
Logout does not recall JWTs already issued; those expire within their short life.
Key rotation retains only old public keys; overlap is not persisted across restart.

The session tests cover all roles, demotion/removal timing, refresh races, logout,
outages, backwards clocks, the ten-hour boundary and a full HTTPS broker lifecycle.
An independent JWK parser checks that published public keys verify issued tokens.
The session authority is independent of HTTP route registration.

The JWT retains `token_class: "human"` to distinguish user credentials from
machine credentials. This class identifies the subject, not the package or
authentication method.

## Authorizing protected service routes

`deviceauth.VerifyPrincipal` applies the complete device-authorization token
contract before returning `authz.Principal{ID: claims.Subject, Roles:
[]string{claims.Role}}`. The role is taken only from verified signed claims.
Applications must not construct a principal from an unverified JWT or a
caller-selected role.

For HTTP consumers, `deviceauth.Middleware` performs that verification and sets
the existing generic `authz` principal context. Install it before
`authz.NewMiddleware` on protected service routes:

```go
import (
    "crypto/rsa"
    "net/http"

    "github.com/openchami/tokensmith/pkg/authz"
    "github.com/openchami/tokensmith/pkg/deviceauth"
)

func protectedNodes(
    policy deviceauth.Config,
    trustedKey func(string) (*rsa.PublicKey, error),
    authorizer *authz.Authorizer,
    nodes http.Handler,
) (http.Handler, error) {
    authenticate, err := deviceauth.Middleware(policy, trustedKey)
    if err != nil {
        return nil, err
    }
    authorize := authz.NewMiddleware(
        authorizer,
        authz.PathMethodMapper{MethodToAction: authz.MethodToActionREST()},
        authz.WithMode(authz.ModeEnforce),
        authz.WithRequireAuthn(true),
    )
    return authenticate(authorize.Handler(nodes)), nil
}
```

Construct `authorizer` using the existing Casbin policy loader and the service's
own model and rules; see [the Casbin-first guide](casbin-first-guide.md). For
example, a policy for the `/nodes` object can grant `role:viewer` `read`,
`role:operator` `read`/`write`, and `role:admin` `read`/`write`/`delete`. The
path/method mapper above maps GET to `read`, POST to `write` and DELETE to
`delete`. A valid viewer token can read `/nodes` but receives 403 for POST or
DELETE when the policy grants no such permission. Missing, invalid or expired
credentials receive 401 before the authorization middleware or service handler
runs. Unmapped or unauthorized actions remain denied by the existing policy.

`policy` and `trustedKey` are administrator-controlled inputs. Resolve key IDs
only against keys trusted for `policy.ClusterIssuer`, with a bounded JWKS cache
and rotation policy; never use a token-selected issuer or key URL. The HTTP
middleware uses the host clock, whose total error must stay within
`policy.SkewSeconds`. Strict token expiry and the membership/session budgets are
checked by `Verify`; the generic AuthN middleware's default clock leeway is not
used. The shared `Config.Validate` still requires `ClientID` and `VerifierFile`.
The consumer does not read `VerifierFile` or need the private membership-verifier
credential: that credential stays only with the issuing broker.

This bridge targets `authz.NewMiddleware`'s generic net/http context. The
`authz/chi` helpers have a separate principal context and require explicit
service wiring. Existing generic `authn.Middleware` parses a different claims
contract and is not a replacement for the device-authorization verifier.
Apply this chain to protected consumer resources, not the broker's public
approval-start/poll endpoints. Route registration and allowed actions remain
service-owned.

## Opt-in TokenSmith integration

Enable device-authorization endpoints with the `device_auth` section in
TokenSmith's JSON config.

Omitting it leaves existing endpoints and credentials unchanged. Example values
below describe a hypothetical registration, not a ready-to-use application:

```json
{
  "device_auth": {
    "issuer": "https://gitlab.example.org",
    "client_id": "REGISTERED_APPLICATION_ID",
    "project_id": 123,
    "cluster_issuer": "https://tokens.example.org",
    "audience": "openchami-device-auth",
    "verifier_file": "/run/secrets/gitlab-membership-verifier",
    "cache_seconds": 90,
    "token_seconds": 180,
    "skew_seconds": 30,
    "absolute_seconds": 36000
  }
}
```

### Optional GitLab role mapping

Omit `gitlab_role_mapping` (or set it to `null`) to retain the default assignment:
Owner/Maintainer → `admin`, Developer → `operator`, Reporter → `viewer`, and
Guest/nonmember → denied. The mapping selects the role signed into the token;
consumer services still use Casbin rules to decide what that role can do.

To replace the assignment, add this optional object inside `device_auth`:

```json
{
  "gitlab_role_mapping": {
    "owner": "admin",
    "maintainer": "operator",
    "developer": "viewer"
  }
}
```

A supplied object is a **complete replacement**, not a merge with defaults. This
example grants Maintainers `operator` and Developers `viewer`; Reporters and
Guests are denied because they are not listed. Even Owner is denied if omitted.
An explicit empty object (`"gitlab_role_mapping": {}`) denies every role. Empty
objects are preserved when configuration is saved and loaded; they never revert
to the default mapping.

Keys are case-sensitive: `owner`, `maintainer`, `developer`, `reporter`, `guest`.
Values must be `admin`, `operator` or `viewer`; omit a key to deny that role.
Unknown names and empty/unknown target values fail startup validation. Guest
access is possible only through an explicit mapping. Nonmembers and unrecognized
GitLab access levels are always denied. Role names and membership are never taken
from the login request.

The broker snapshots the mapping before serving. Changing the original Go map
cannot replace active policy; apply configuration changes by restarting the
broker, which requires fresh session approval. Existing JWTs expire normally.
Renewal re-evaluates verified membership using the configured mapping when its
membership cache expires, within the existing cache/token/clock budget.

Register a GitLab application with device authorization and `read_user`. Provision
an independent project API credential able to read effective membership, such
as a Reporter credential with `read_api`. Put its value in the private verifier
file (0600), not JSON or command arguments. Keep the existing TokenSmith signing
key persistent. `cluster_issuer` must match the service issuer and its signing
algorithm must be PS256. A bad configuration fails at startup.
Existing OIDC/service configuration remains required by the current server CLI.

Serve the broker through HTTPS. Device-authorization endpoints accept only POST
requests with `Content-Type: application/json`; responses have
`Cache-Control: no-store`:

| Route | Request | Result |
| --- | --- | --- |
| `/device-auth/start` | `{}` | Public approval URL/code, polling interval and broker transaction handle. |
| `/device-auth/poll` | `{"transaction":"BROKER_HANDLE"}` | Pending/slow-down, or cluster token plus private renewal handle. |
| `/device-auth/renew` | `{}` plus renewal handle as a Bearer credential | Short cluster token; unchanged absolute deadline. |
| `/device-auth/logout` | `{}` plus renewal handle as a Bearer credential | Renewal removed; upstream access revoked when reachable. |

The client must protect transaction/renewal handles like credentials. The broker
never accepts caller-selected identity, role, application or project fields.
Device-authorization routes bypass the legacy request-metadata logger, including
rejected query strings; audit events contain only verified IDs, role, time and
fixed outcomes.

The integration reuses the existing PS256 key and existing JWKS handler. It does
not replace OAuth exchange, revocation, local-peer protection or mTLS service
identity. Key rotation during maintenance must coordinate cached consumers; there
is no live rotation API or persistent session database.

TokenSmith issues user credentials; downstream services are responsible for
gateway configuration and route enforcement. Consumers must use the
device-authorization verifier and authorize actual actions. The GitHub, Entra and Google transport-only
login stubs cannot be selected as TokenSmith device-login backends.

Run `go test -race -shuffle=on -count=1 ./...` and `go vet ./...`. The
device-authorization suites need only local HTTPS listeners and synthetic
credentials. No account approval, provider credentials, cluster deployment or
live permission change is involved.
