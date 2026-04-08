<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Internal service-to-service AuthN/AuthZ

This guide is for services that only need **internal service-to-service** authentication and authorization.

Use this when:

- clients are other trusted services (not end users)
- caller services obtain service JWTs from TokenSmith
- target services enforce TokenSmith JWT AuthN + Casbin AuthZ via TokenSmith middleware

For normative wire behavior and contract details, see:

- `docs/authz-spec.md`
- `docs/authz_contract.md`

## 1) Caller service: obtain service tokens from bootstrap token

Use `pkg/tokenservice` in the caller service to redeem startup bootstrap tokens for service JWTs.

Canonical exchange endpoint:

- `POST /service/token`

Canonical request body:

```json
{
  "grant_type": "bootstrap_token",
  "bootstrap_token": "<jwt>",
  "target_service": "metadata-service",
  "scopes": ["read"]
}
```

Refresh request body:

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "<jwt>",
  "target_service": "metadata-service",
  "scopes": ["read"]
}
```

Notes:

- `target_service` and `scopes` are optional in the request body.
- If omitted, TokenSmith uses the allowed target/scopes embedded in the bootstrap token.

Canonical response body:

```json
{
  "token": "<service-jwt>",
  "expires_at": "2026-03-25T18:47:12Z",
  "refresh_token": "<refresh-jwt>",
  "refresh_expires_at": "2026-03-26T18:47:12Z"
}
```

Compatibility guarantees for `POST /service/token`:

- Request fields `grant_type`, `bootstrap_token`, `refresh_token`, `target_service`, and `scopes` are stable.
- Response fields `token`, `expires_at`, `refresh_token`, and `refresh_expires_at` are stable.
- Invalid or expired bootstrap token returns `401 Unauthorized`.
- One-time bootstrap token reuse returns `401 Unauthorized`.
- Target mismatch between request and bootstrap allowance returns `401 Unauthorized`.
- Requested scopes outside bootstrap allowance return `401 Unauthorized`.

### Bootstrap mint and distribution

1. Mint a short-lived one-time bootstrap token before service startup:

```bash
BOOTSTRAP_TOKEN=$(tokensmith mint-bootstrap-token \
  --key-file ./keys/private.pem \
  --service-id example-service-1 \
  --target-service metadata-service \
  --scopes read \
  --ttl 5m)
```

1. Start the caller service with:

```bash
export TOKENSMITH_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
```

1. Caller redeems this token once at `POST /service/token` (`grant_type=bootstrap_token`) and receives access + refresh tokens.

1. TokenSmith enforces one-time use using bootstrap-token `jti` tracking.
1. For restart-safe replay protection, start TokenSmith with `--bootstrap-jti-store /path/to/bootstrap-jti.json` (or `TOKENSMITH_BOOTSTRAP_JTI_STORE`).
1. Caller renews service JWTs using `grant_type=refresh_token` until the refresh token expires.

### Shared client usage (`pkg/tokenservice/client.go`)

`ServiceClient` is the canonical client for callers that exchange bootstrap tokens
for access + refresh tokens and renew using the refresh grant.

Recommended consumer environment variables:

- `TOKENSMITH_URL`: Base URL of TokenSmith, for example `http://tokensmith:8080`
- `TOKENSMITH_BOOTSTRAP_TOKEN`: One-time bootstrap token
- `TOKENSMITH_TARGET_SERVICE`: Target audience service name
- `TOKENSMITH_SCOPES`: Comma-separated scopes for token exchange
- `TOKENSMITH_REFRESH_SKEW_SEC`: Refresh threshold in seconds

Example wiring:

```go
client := tokenservice.NewServiceClientWithOptions(
  os.Getenv("TOKENSMITH_URL"),
  "boot-service",
  "boot-service-id",
  "instance-1",
  "cluster-1",
  tokenservice.WithBootstrapToken(os.Getenv("TOKENSMITH_BOOTSTRAP_TOKEN")),
  tokenservice.WithTargetService(os.Getenv("TOKENSMITH_TARGET_SERVICE")),
  tokenservice.WithScopes(strings.Split(os.Getenv("TOKENSMITH_SCOPES"), ",")),
  tokenservice.WithRefreshBefore(120*time.Second),
)

if err := client.Initialize(ctx); err != nil {
  return err
}

go client.StartAutoRefresh(ctx)
```

`Initialize` performs a blocking startup exchange with bounded retry and
exponential backoff before failing closed. Default behavior is 5 attempts,
starting at 1 second and capping at 15 seconds. Callers can override this with
`WithBootstrapMaxAttempts`, `WithBootstrapInitialBackoff`, and
`WithBootstrapMaxBackoff`.

`Initialize` performs the bootstrap exchange once. Subsequent renewals use the
refresh grant automatically. `StartAutoRefresh` exits when refresh token expiry
is reached and renewal can no longer proceed.

Callers should treat refresh failures as degraded service state and expose
`client.Stats()` in logs or health diagnostics.

## 2) Target service: validate JWTs and enforce policy

Install middleware in this order:

1. TokenSmith AuthN middleware (TokenSmith JWT validation and principal extraction)
1. TokenSmith AuthZ middleware (Casbin decision)

TokenSmith AuthN writes principal into the context expected by TokenSmith AuthZ,
so no service-specific bridge middleware is required between these two layers.

Reference wiring:

- `examples/minisvc/main.go`
- `examples/minisvc/mapper.go`

## 3) Policy and role mapping

Ensure service principals map to role `service` in policy/grouping. The baseline role model includes `service` for service-to-service calls.

Reference files:

- `examples/minisvc/policy/model.conf`
- `examples/minisvc/policy/policy.csv`
- `examples/minisvc/policy/grouping.csv`

Normative requirements:

- `docs/authz_contract.md#service-principal-requirements`
- `docs/authz_contract.md#rbac-role-model-minimum-required-roles`

## 4) Rollout mode

Roll out per service using:

1. `off`
2. `shadow`
3. `enforce`

Operational guidance:

- `docs/authz_operations.md`

## 5) Recommended integration checklist

- Caller receives `TOKENSMITH_BOOTSTRAP_TOKEN` at startup and redeems once via `pkg/tokenservice`
- Target installs AuthN before AuthZ
- Routes are mapped via `authz.RouteMapper` or path/method mapping
- Service principals resolve to role `service`
- Service runs through off → shadow → enforce rollout
- Operators track `policy_version` in logs/deny responses
