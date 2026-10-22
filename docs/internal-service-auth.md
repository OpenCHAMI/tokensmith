<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Internal service-to-service AuthN/AuthZ

This guide is for services that only need internal service-to-service authentication and authorization.

This is the canonical `pkg/tokenservice.ServiceClient` lifecycle contract.

Use this path when:

- callers are trusted services, not end users
- caller services obtain TokenSmith-issued service JWTs at startup
- target services validate TokenSmith JWTs and enforce Casbin policy with TokenSmith middleware

For normative behavior, see:

- `docs/authz-spec.md`
- `docs/authz_contract.md`
- `docs/http-endpoints.md`

## 1) Configure target services to verify TokenSmith JWTs

Target services validating TokenSmith-issued JWTs should configure verifiers with the direct JWKS URL:

- `GET /.well-known/jwks.json`

Example verifier configuration value:

```text
https://tokensmith.example/.well-known/jwks.json
```

Important:

- TokenSmith currently exposes a direct JWKS endpoint
- TokenSmith does not currently publish its own OIDC discovery document at `/.well-known/openid-configuration`
- configure verifiers with the JWKS URL directly
- the `kid` in TokenSmith-issued JWTs is expected to match a key in the published set

## 2) Caller service flow: mTLS service identity (preferred) or bootstrap token

The service-to-service token flow uses the RFC 8693 token endpoint:

- canonical endpoint: `POST /oauth/token`
- compatibility alias: `POST /token`

For new integrations, prefer `POST /oauth/token`.

### Service identity mTLS request (preferred)

Caller services can mint startup session credentials by presenting a client certificate:

- endpoint: `POST /service-identity/session`
- method: `POST`
- body: empty JSON `{}` (or empty body)
- TLS: client certificate required; certificate must chain to TokenSmith `--service-identity-ca`

Example:

```bash
curl -s https://tokensmith.example/service-identity/session \
  --cert /etc/openchami/tls/service.crt \
  --key /etc/openchami/tls/service.key \
  -X POST | jq
```

`pkg/tokenservice.ServiceClient` behavior:

- if both `TOKENSMITH_SERVICE_IDENTITY_CERT` and `TOKENSMITH_SERVICE_IDENTITY_KEY` are set and readable, it uses `POST /service-identity/session`
- else, it falls back to bootstrap token exchange via `POST /oauth/token`
- when a refresh family is terminal and cert plus key are configured, it attempts one HTTPS `POST /service-identity/session` replacement; bootstrap-only callers return `ErrRefreshTokenExpired`, while mTLS reacquisition failures propagate their wrapped reauthentication, material, or HTTP error and preserve the old state
- a consumed bootstrap token is never replayed as a fallback after that terminal point

### Dedicated service identity policy

Use `tokensmith service-identity-policy create`, `list`, and `revoke` to manage per-subject mTLS authorization.

Important:

- the policy store is separate from the bootstrap and refresh stores
- the default store path is `./data/service-identities`
- override it with `--service-identity-policy-store` or `TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE`
- `list` returns metadata only, not tokens or secrets
- `--refresh-ttl` must be positive and must not exceed `--ttl`
- policy expiry and revocation are independent of bootstrap token state and refresh-family state
- bootstrap tokens never authorize `POST /service-identity/session`
- existing mTLS callers must have a dedicated policy before upgrade, TokenSmith does not migrate them automatically

### Bootstrap token request

Request format:

- method: `POST`
- content type: `application/x-www-form-urlencoded`

Required form fields:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<bootstrap-token>
subject_token_type=urn:openchami:params:oauth:token-type:bootstrap-token
```

Example:

```bash
curl -s https://tokensmith.example/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token=<bootstrap-token>' \
  --data-urlencode 'subject_token_type=urn:openchami:params:oauth:token-type:bootstrap-token'
```

Successful response shape:

```json
{
  "access_token": "<service-jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque-refresh-token>",
  "refresh_expires_in": 86400,
  "scope": "read",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access-token"
}
```

### Refresh token request

```bash
curl -s https://tokensmith.example/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'refresh_token=<opaque-refresh-token>'
```

### Error behavior you should expect

Observed error responses are OAuth-style JSON:

```json
{
  "error": "invalid_grant",
  "error_description": "The provided token is invalid or has already been used"
}
```

Observed status codes for this flow include:

- `400 Bad Request`
- `405 Method Not Allowed`
- `429 Too Many Requests`
- `500 Internal Server Error`

Observed error codes include:

- `invalid_request`
- `unsupported_grant_type`
- `invalid_grant`
- `too_many_requests`
- `server_error`

### Security-relevant behavior

- bootstrap tokens are one-time use
- reusing a consumed bootstrap token fails with `invalid_grant`
- failed bootstrap exchanges are throttled per client IP
- refresh tokens are rotated on every successful use
- replaying an old rotated refresh token revokes the entire token family

## 3) Mint and distribute bootstrap tokens

Preferred flow for RFC 8693: create an opaque bootstrap token with server-side policy.

Important:

- Use the same bootstrap store path for both TokenSmith and bootstrap token creation.
- If paths differ, TokenSmith cannot find the token policy and exchange will fail with `invalid_grant`.
- Bootstrap token creation is a **strictly local operation** to the TokenSmith runtime context.
- In practice, run `tokensmith bootstrap-token create` on the same host/container namespace where TokenSmith can read the same store path.

### Podman Quadlet workflow (recommended for OpenCHAMI)

If TokenSmith is deployed with Podman Quadlets, mint bootstrap tokens from the same host using `podman exec` so store-path coupling is guaranteed.

Example (conceptual):

```bash
# TokenSmith quadlet mounts /var/lib/tokensmith/bootstrap into container
# and serve uses --rfc8693-bootstrap-store /var/lib/tokensmith/bootstrap

BOOTSTRAP_TOKEN=$(podman exec tokensmith \
  tokensmith bootstrap-token create \
    --subject example-service-1 \
    --audience metadata-service \
    --scopes "read" \
    --ttl 10m \
    --refresh-ttl 24h \
    --bootstrap-store /var/lib/tokensmith/bootstrap \
    --output-format json | jq -r '.bootstrap_token')
```

Why this matters:

- `bootstrap-token create` persists server-side policy files.
- `/oauth/token` exchange succeeds only when TokenSmith can read those policy files.
- Running minting on a different machine without shared storage will produce `invalid_grant`.

Start TokenSmith with durable stores:

```bash
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --issuer http://localhost:8080 \
  --oidc-issuer https://issuer.example \
  --rfc8693-bootstrap-store ./data/bootstrap-tokens \
  --rfc8693-refresh-store ./data/refresh-tokens
```

Then mint a short-lived opaque bootstrap token against that same store path:

```bash
BOOTSTRAP_TOKEN=$(tokensmith bootstrap-token create \
  --subject example-service-1 \
  --audience metadata-service \
  --scopes "read" \
  --ttl 10m \
  --refresh-ttl 24h \
  --bootstrap-store ./data/bootstrap-tokens \
  --output-format json | jq -r '.bootstrap_token')
```

Start the caller service with:

```bash
export TOKENSMITH_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
```

### Verify immediately (first success checkpoint)

After minting, validate the token exchange before wiring callers:

```bash
curl -s http://localhost:8080/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$BOOTSTRAP_TOKEN" \
  --data-urlencode 'subject_token_type=urn:openchami:params:oauth:token-type:bootstrap-token' | jq .
```

Expected result:

- `access_token` and `refresh_token` present
- no `invalid_grant` error

Defaults when unset:

- bootstrap store: `./data/bootstrap-tokens`
- refresh store: `./data/refresh-tokens`

## 4) Use the shared client (`pkg/tokenservice/client.go`)

`ServiceClient` is the canonical caller-side client for bootstrap exchange, refresh rotation, terminal mTLS recovery, and attaching bearer tokens to downstream requests.

Recommended caller configuration:

- `TOKENSMITH_URL`: base URL of the TokenSmith service
- `TOKENSMITH_BOOTSTRAP_TOKEN`: one-time bootstrap token
- `TOKENSMITH_SERVICE_IDENTITY_CERT`: service mTLS client certificate path
- `TOKENSMITH_SERVICE_IDENTITY_KEY`: service mTLS client private key path
- `TOKENSMITH_TARGET_SERVICE`: consumer-side config convention for intended audience

Important implementation note:

- current server-side issuance is determined by the bootstrap-token policy and refresh-token family
- `pkg/tokenservice.ServiceClient` sends RFC 8693 bootstrap and refresh form fields only; `WithTargetService` is client-local metadata (not sent to the server) used for validation and audit logging

### Lifecycle contract

- `Initialize` blocks until the first token exchange succeeds or the configured retry budget is exhausted. It only retries failures that are still safely pre-send, so a bootstrap credential may be spent after a request reaches TokenSmith and the next lifecycle call must start from fresh material.
- `GetToken` preserves compatibility by returning without a lifecycle request while the cached access token is fresh. `RefreshTokenIfNeeded` has the same fresh-token no-op behavior.
- `ForceRefresh` is the explicit API for callers that require acquisition or rotation even while the cached access token is fresh.
- `GetToken`, `ForceRefresh`, and `RefreshTokenIfNeeded` share one operation-owned bounded context when a lifecycle request is needed. Concurrent callers wait on the same success or failure, and each caller only cancels its own wait.
- Completion is atomic. The client either publishes one new token state or leaves the previous state untouched on failure.
- Refresh rotation does not extend the absolute refresh-family deadline. `refresh_expires_in` is the remaining family lifetime at the moment the server replies.
- When the access token needs renewal, a still-valid refresh family uses `POST /oauth/token` with the refresh grant. A refresh replay revokes the family and the current refresh generation, but it does not revoke an already-issued access JWT.
- Access-token revocation remains separate and is handled through `/oauth/revoke` by `jti`.
- When the refresh family is terminal, configured cert plus key trigger one HTTPS `POST /service-identity/session` replacement. Bootstrap-only callers return the exact `ErrRefreshTokenExpired` error, and the consumed bootstrap token is not replayed.
- If that terminal mTLS replacement fails, the current auto-refresh loop stops. A later explicit lifecycle call can retry after the underlying cause is fixed.

### `ServiceClientStats`

Stats are operation-level. They describe the last token lifecycle attempt, not each caller wait.

| Field | Meaning |
| --- | --- |
| `RefreshSuccesses` | Number of successful token lifecycle operations, including initial acquisition, refresh, and replacement |
| `RefreshFailures` | Number of failed token lifecycle operations recorded by the client |
| `LastError` | Last refresh-related error string |
| `LastRefresh` | Time of the last recorded token lifecycle operation |
| `LastSuccess` | Time of the last successful token acquisition, refresh, or replacement |
| `HasToken` | Whether an access token is currently cached |
| `ExpiresAt` | Cached access token expiry |
| `HasRefreshToken` | Whether a refresh token is currently cached |
| `RefreshExpiresAt` | Absolute refresh-family deadline for the cached refresh token family |

`RefreshExpiresAt` does not advance beyond the original family deadline on rotation. It tracks the family deadline, not a fresh lease.

When persistence helpers report a durability error after a write or rename, treat the one-time credential as potentially committed and verify the stored state before retrying.

`refresh_family_id` values are opaque generated identifiers and may differ across processes or runs.

Example wiring:

```go
client := tokenservice.NewServiceClientWithOptions(
  os.Getenv("TOKENSMITH_URL"),
  "boot-service",
  "boot-service-id",
  "instance-1",
  "cluster-1",
  tokenservice.WithBootstrapToken(os.Getenv("TOKENSMITH_BOOTSTRAP_TOKEN")),
  tokenservice.WithServiceIdentityCertKey(
    os.Getenv("TOKENSMITH_SERVICE_IDENTITY_CERT"),
    os.Getenv("TOKENSMITH_SERVICE_IDENTITY_KEY"),
  ),
  tokenservice.WithTargetService("metadata-service"),
  tokenservice.WithRefreshBefore(120*time.Second),
)

if err := client.Initialize(ctx); err != nil {
  return err
}

go client.StartAutoRefresh(ctx)

// GetToken is a no-op while the cached access token is fresh.
if err := client.GetToken(ctx); err != nil {
  return err
}

// ForceRefresh explicitly requests a new token.
if err := client.ForceRefresh(ctx); err != nil {
  return err
}
```

`Initialize` performs a blocking startup exchange with bounded retry and exponential backoff before failing closed.

Current defaults:

- max attempts: `5`
- initial backoff: `1s`
- max backoff: `15s`
- refresh threshold: `5m`
- auto-refresh check interval: `1m`

Callers can override these with:

- `WithBootstrapMaxAttempts`
- `WithBootstrapInitialBackoff`
- `WithBootstrapMaxBackoff`
- `WithRefreshBefore`
- `WithAutoRefreshInterval`

Expose `client.Stats()` in logs or diagnostics to understand refresh success, failure, and current token state.

## 5) Target service middleware order

Install middleware in this order:

1. request ID / access logging middleware
2. TokenSmith AuthN middleware
3. TokenSmith AuthZ middleware
4. application handler

TokenSmith AuthN writes principal into both authn and authz context helpers, so no service-specific bridge middleware is required between them.

Reference wiring:

- `examples/minisvc/main.go`
- `examples/minisvc/mapper.go`
- `docs/context-guide.md`

## 6) Policy and role mapping

Ensure service principals resolve to role `service` in policy/grouping.

Reference files:

- `examples/minisvc/policy/model.conf`
- `examples/minisvc/policy/policy.csv`
- `examples/minisvc/policy/grouping.csv`

Normative requirements:

- `docs/authz_contract.md#service-principal-requirements`
- `docs/authz_contract.md#rbac-role-model-minimum-required-roles`

## 7) Rollout mode

Recommended rollout sequence per service:

1. `off`
2. `shadow`
3. `enforce`

Operational guidance:

- `docs/authz_operations.md`

## 8) Integration checklist

- caller receives `TOKENSMITH_BOOTSTRAP_TOKEN` at startup
- caller exchanges bootstrap token once via `pkg/tokenservice` or `POST /oauth/token`
- target service validates JWTs with the direct JWKS URL
- target installs AuthN before AuthZ
- routes are mapped explicitly or by path/method strategy
- service principals resolve to role `service`
- rollout proceeds through off → shadow → enforce
- operators track `policy_version` in logs and deny responses
