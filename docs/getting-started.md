<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith getting started

This guide is the fastest path to running TokenSmith and integrating AuthN/AuthZ in a service.

`pkg/authn` validates TokenSmith JWTs. The expected claim set includes standard JWT claims plus TokenSmith claims such as `auth_level`, `auth_factors`, `auth_methods`, `session_id`, `session_exp`, and `auth_events`. TokenSmith-issued JWTs include RFC 7638 `kid` thumbprints, and middleware requires a valid RFC 7638 `kid` header for verification.

If you need normative behavior details, see:

- `docs/authz-spec.md`
- `docs/authz_contract.md`

## 1) Start the token service

Generate a default config file:

```bash
tokensmith generate-config --config ./config.json
```

Start TokenSmith:

```bash
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --oidc-issuer https://issuer.example \
  --oidc-client-id your-client-id
```

If `--oidc-client-id` or `--oidc-client-secret` are not provided, TokenSmith falls back to `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.

See full command options in `docs/cli-reference.md`.

## 1.1) JWKS endpoint

TokenSmith publishes its active public signing keys at:

- `GET /.well-known/jwks.json`

This endpoint returns the JWKS used to validate TokenSmith-issued JWTs.

Current behavior:

- response content type is `application/json`
- the response body contains a standard `keys` array
- each published RSA key includes `kty`, `use`, `alg`, `kid`, `n`, and `e`

Operational guidance:

- treat `/.well-known/jwks.json` as the canonical verification endpoint for TokenSmith-issued JWTs
- TokenSmith currently does not publish its own OIDC discovery document at `/.well-known/openid-configuration`
- configure JWT verifiers with the direct JWKS URL
- cache keys according to verifier policy and plan for outage/rotation behavior

Example:

```bash
curl -s http://localhost:8080/.well-known/jwks.json | jq
```

For JWKS validation behavior, caching, and failure semantics, see:

- `docs/http-endpoints.md`
- `docs/authz-spec.md#6-jwks-caching-and-failure-semantics`
- `docs/security-notes.md#jwks-caching-and-availability-risks`

## 1.5) Internal service-to-service only (no external user token exchange)

Standalone quick guide:

- `docs/internal-service-auth.md`

If your service only needs internal service-to-service AuthN/AuthZ, you can skip end-user token-exchange details and use this path:

1. Mint a one-time bootstrap token with `tokensmith mint-bootstrap-token`.
2. Pass the token via `TOKENSMITH_BOOTSTRAP_TOKEN` to the caller service process.
3. Have the caller service redeem the token at `POST /oauth/token` using `pkg/tokenservice` or `example/serviceauth`.
4. In the target service, install TokenSmith AuthN middleware to validate TokenSmith JWTs and build a verified principal.
5. Install TokenSmith AuthZ middleware and map routes using either explicit `authz.RouteMapper` or path/method style (`authz.PathMethodMapper` plus Casbin matchers).
6. Ensure service principals map to the `service` role in policy/grouping.

Current examples:

- `example/serviceauth` (service token acquisition/refresh)
- `examples/minisvc/main.go` (AuthN + AuthZ middleware wiring)
- `examples/minisvc/policy/` (Casbin model/policy/grouping)

Normative requirements for service principals:

- `docs/authz_contract.md#service-principal-requirements`
- `docs/authz_contract.md#integration-checklist-services`

## 1.2) Endpoint overview

The TokenSmith service currently exposes these user-facing endpoints:

- `GET /health`
- `GET /.well-known/jwks.json`
- `POST /oauth/token`
- `POST /token` (alias for the service-token flow)

See `docs/http-endpoints.md` for request/response formats and failure behavior.

## 1.3) Key material and token-state storage

Current startup behavior:

- if `--key-file` is set, TokenSmith loads the existing private key
- if `--key-file` is not set, TokenSmith generates an RSA keypair and writes `private.pem` and `public.pem` under `--key-dir`
- bootstrap token policies are stored in `./data/bootstrap-tokens` unless overridden
- refresh token families are stored in `./data/refresh-tokens` unless overridden

For production, use durable storage paths for the RFC 8693 stores.

## 2) Pick an AuthZ integration style

TokenSmith supports two common patterns:

1. **Explicit route mapping** (`object`, `action`) via `authz.RouteMapper`
2. **Path/method style** using Casbin matchers such as `keyMatch2`

The smallest working example that includes both styles is:

- `examples/minisvc/main.go`
- `examples/minisvc/policy/model.conf`
- `examples/minisvc/policy/policy.csv`
- `examples/minisvc/policy/grouping.csv`

Reference guide:

- `docs/casbin-first-guide.md`

## 3) Configure policy loading

By default, TokenSmith uses an embedded baseline Casbin model and policy.

To add policy fragments from disk, set one of:

- `TOKENSMITH_POLICY_DIR` (preferred)
- `AUTHZ_POLICY_DIR`

Policy fragments are loaded at process startup in lexical filename order. Hot reload is not supported in v1.

Details:

- `docs/authz_policy.md`

## 4) Roll out safely: off -> shadow -> enforce

Recommended rollout sequence per service:

1. `off`: verify middleware wiring and principal extraction
2. `shadow`: evaluate policy without blocking requests
3. `enforce`: block denied requests with stable TokenSmith error response

Operational guidance:

- `docs/authz_operations.md`

## 5) Verify what is running

Track `policy_version` from startup logs and deny responses to confirm policy consistency across replicas.

If you use chi-specific middleware diagnostics, expose:

- `chi.DiagnosticsHandler(mode, policyVersion, policySource)`

from:

- `pkg/authz/chi/diagnostics.go`

Recommended operator workflow (including endpoint wiring and rollout checks):

- `docs/authz_operations.md#diagnostics-endpoint-recommended`
- `docs/authz_operations.md#rollout-verification-playbook`

## 6) Use canonical principal context helpers

For new services, use canonical principal helpers:

- `authz.SetPrincipal(ctx, p)`
- `authz.PrincipalFromContext(ctx)`

When your service uses `authn.Middleware`, TokenSmith already writes principal
to both authn and authz context helpers. No additional bridge middleware is
required between AuthN and AuthZ.

Reference details:

- `docs/context-guide.md`
