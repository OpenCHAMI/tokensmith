<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Internal service-to-service AuthN/AuthZ

This guide is for services that only need internal service-to-service authentication and authorization.

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

## 2) Caller service flow: bootstrap token to service token

The service-to-service token flow uses the RFC 8693 token endpoint:

- canonical endpoint: `POST /oauth/token`
- compatibility alias: `POST /token`

For new integrations, prefer `POST /oauth/token`.

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

Mint a short-lived bootstrap token before service startup:

```bash
BOOTSTRAP_TOKEN=$(tokensmith mint-bootstrap-token \
  --key-file ./keys/private.pem \
  --service-id example-service-1 \
  --target-service metadata-service \
  --scopes read \
  --ttl 5m)
```

Start the caller service with:

```bash
export TOKENSMITH_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
```

For restart-safe replay protection and refresh-family persistence, start TokenSmith with durable stores:

```bash
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --rfc8693-bootstrap-store ./data/bootstrap-tokens \
  --rfc8693-refresh-store ./data/refresh-tokens
```

Defaults when unset:

- bootstrap store: `./data/bootstrap-tokens`
- refresh store: `./data/refresh-tokens`

## 4) Use the shared client (`pkg/tokenservice/client.go`)

`ServiceClient` is the canonical caller-side client for bootstrap exchange, refresh rotation, and attaching bearer tokens to downstream requests.

Recommended caller configuration:

- `TOKENSMITH_URL`: base URL of the TokenSmith service
- `TOKENSMITH_BOOTSTRAP_TOKEN`: one-time bootstrap token
- `TOKENSMITH_TARGET_SERVICE`: consumer-side config convention for intended audience

Important implementation note:

- current server-side issuance is determined by the bootstrap-token policy and refresh-token family
- `pkg/tokenservice.ServiceClient` sends RFC 8693 bootstrap and refresh form fields only; `WithTargetService` is client-local metadata (not sent to the server) used for validation and audit logging

Example wiring:

```go
client := tokenservice.NewServiceClientWithOptions(
  os.Getenv("TOKENSMITH_URL"),
  "boot-service",
  "boot-service-id",
  "instance-1",
  "cluster-1",
  tokenservice.WithBootstrapToken(os.Getenv("TOKENSMITH_BOOTSTRAP_TOKEN")),
  tokenservice.WithTargetService("metadata-service"),
  tokenservice.WithRefreshBefore(120*time.Second),
)

if err := client.Initialize(ctx); err != nil {
  return err
}

go client.StartAutoRefresh(ctx)
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
