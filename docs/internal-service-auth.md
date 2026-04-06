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
  "bootstrap_token": "<jwt>",
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
  "expires_at": "2026-03-25T18:47:12Z"
}
```

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

1. Caller redeems this token once at `POST /service/token` and receives a regular service JWT for S2S calls.

1. TokenSmith enforces one-time use using bootstrap-token `jti` tracking.
1. For restart-safe replay protection, start TokenSmith with `--bootstrap-jti-store /path/to/bootstrap-jti.json` (or `TOKENSMITH_BOOTSTRAP_JTI_STORE`).
1. If a caller needs a new service JWT after bootstrap consumption, provision a new bootstrap token and update `TOKENSMITH_BOOTSTRAP_TOKEN` before requesting again.

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
