<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith getting started

This guide is the fastest path to running TokenSmith and integrating AuthN/AuthZ in a service.

## Which path applies to me?

Start here to find the right guide for your situation:

1. **I have an external OIDC provider (Keycloak, Azure AD, Okta, Dex, etc.) and want to use it for authentication**
   - Follow section [1) Start the token service](#1-start-the-token-service) below
   - Details: [Token Flows: Upstream OIDC](./token-flows.md#upstream-oidc-flow-recommended)

2. **TokenSmith is down or I need emergency access without OIDC**
   - Use the break-glass local user token flow: [Break-glass: Local user tokens](#break-glass-local-user-tokens)
   - Details: [Token Flows: Local user token](./token-flows.md#local-user-token-flow-break-glass)

3. **I'm setting up service-to-service authentication only (no end-user OIDC)**
   - Jump to: [1.3) Internal service-to-service only](#13-internal-service-to-service-only-no-external-user-token-exchange)
   - Details: [Internal service auth guide](./internal-service-auth.md)

4. **I'm troubleshooting or debugging something**
   - See: [Troubleshooting Guide](./troubleshooting.md)

5. **I need to understand token claims and what's in a JWT**
   - See: [Claim Reference](./claim-reference.md)

---

`pkg/authn` validates TokenSmith JWTs. The expected claim set includes standard JWT claims plus TokenSmith claims such as `auth_level`, `auth_factors`, `auth_methods`, `session_id`, `session_exp`, and `auth_events`. TokenSmith-issued JWTs include RFC 7638 `kid` thumbprints, and middleware requires a valid RFC 7638 `kid` header for verification.

If you need normative behavior details, see:

- `docs/authz-spec.md`
- `docs/authz_contract.md`

---

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

## 1.2) Break-glass: Local user tokens (emergency access)

**Use case**: When upstream OIDC is unavailable or for initial bootstrapping, you can mint tokens locally without relying on an external provider.

**Important**: This flow is for break-glass and bootstrap scenarios only, not primary production authentication.

### Starting with local user minting enabled

```bash
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --enable-local-user-mint
```

### Minting a local user token

```bash
tokensmith user-token create \
  --subject "admin@example.com" \
  --scopes "admin,read,write" \
  --enable-local-user-mint
```

This outputs a JWT that you can use immediately with your services.

### When to use this

- **Initial bootstrap**: Set up an admin account before external OIDC is configured
- **Disaster recovery**: Emergency access when external OIDC provider is down
- **Testing**: Quick token generation without involving a full OIDC provider

### After OIDC is available

Once your OIDC provider is ready:

1. Configure it with TokenSmith (no restart required):
   ```bash
   tokensmith oidc configure \
     --issuer-url "https://keycloak.example.com/realms/master" \
     --client-id "tokensmith" \
     --replace-existing
   ```

2. Optionally restart TokenSmith without `--enable-local-user-mint` to disable the break-glass path

### Security considerations

- Local user tokens are issued directly by TokenSmith; they do not reflect upstream OIDC identity
- The local-only admin endpoint is only accessible from `localhost`
- Audit logs should record who minted local tokens and when
- See [Security Notes: Local user minting](./security-notes.md#local-user-token-security) for full details

Details: [Token Flows: Local user token flow](./token-flows.md#local-user-token-flow-break-glass)

## 1.3) Internal service-to-service only (no external user token exchange)

Standalone quick guide:

- `docs/internal-service-auth.md`

If your service only needs internal service-to-service AuthN/AuthZ, you can skip end-user token-exchange details and use this path:

1. Start TokenSmith with a durable bootstrap store and refresh store.
2. Exec into the TokenSmith container and mint one bootstrap token per caller service.
3. Pass each caller service its own `TOKENSMITH_BOOTSTRAP_TOKEN` and `TOKENSMITH_URL`.
4. Have the caller service redeem the token at `POST /oauth/token` using `pkg/tokenservice` or `example/serviceauth`.
5. In the target service, install TokenSmith AuthN middleware to validate TokenSmith JWTs and build a verified principal.
6. Install TokenSmith AuthZ middleware and map routes using either explicit `authz.RouteMapper` or path/method style (`authz.PathMethodMapper` plus Casbin matchers).
7. Ensure service principals map to the `service` role in policy/grouping.

### Recommended container workflow

#### Start TokenSmith with bootstrap configured

```bash
podman run -d --name tokensmith \
   -p 8080:8080 \
   -e TOKENSMITH_ISSUER="http://tokensmith:8080" \
   -e TOKENSMITH_PORT="8080" \
   -e TOKENSMITH_CLUSTER_ID="cluster-1" \
   -e TOKENSMITH_OPENCHAMI_ID="openchami-1" \
   -e TOKENSMITH_CONFIG="/etc/tokensmith/config.json" \
   -e TOKENSMITH_KEY_DIR="/var/lib/tokensmith/keys" \
   -e TOKENSMITH_RFC8693_BOOTSTRAP_STORE="/var/lib/tokensmith/bootstrap" \
   -e TOKENSMITH_RFC8693_REFRESH_STORE="/var/lib/tokensmith/refresh" \
   -v ./config.json:/etc/tokensmith/config.json:ro \
   -v ./tokensmith-data:/var/lib/tokensmith \
   <your-tokensmith-image>
```

This is the critical requirement: TokenSmith must be started with a persistent bootstrap store path, and bootstrap-token creation must use that same path.

#### Mint one token for each caller service

```bash
BOOT_SERVICE_TOKEN=$(podman exec tokensmith \
   tokensmith bootstrap-token create \
      --subject boot-service \
      --audience smd \
      --scopes "node:read" \
      --ttl 10m \
      --refresh-ttl 24h \
      --bootstrap-store /var/lib/tokensmith/bootstrap \
      --output-format json | jq -r '.bootstrap_token')

METADATA_SERVICE_TOKEN=$(podman exec tokensmith \
   tokensmith bootstrap-token create \
      --subject metadata-service \
      --audience smd \
      --scopes "node:read" \
      --ttl 10m \
      --refresh-ttl 24h \
      --bootstrap-store /var/lib/tokensmith/bootstrap \
      --output-format json | jq -r '.bootstrap_token')
```

Do not mint one shared bootstrap token and reuse it across multiple services. Bootstrap tokens are one-time-use startup credentials and should map to one caller identity.

#### Pass the matching token to the matching service

```bash
podman run -d --name boot-service \
   -e TOKENSMITH_URL="http://tokensmith:8080" \
   -e TOKENSMITH_BOOTSTRAP_TOKEN="$BOOT_SERVICE_TOKEN" \
   <your-boot-service-image>

podman run -d --name metadata-service \
   -e TOKENSMITH_URL="http://tokensmith:8080" \
   -e TOKENSMITH_BOOTSTRAP_TOKEN="$METADATA_SERVICE_TOKEN" \
   <your-metadata-service-image>
```

Each service should receive only the token minted for that service. The subject, audience, and scopes are enforced server-side from the stored bootstrap policy.

#### What each side should log

Expected TokenSmith success log when a service redeems its bootstrap token:

```text
INF Bootstrap token successfully exchanged for service token subject=boot-service audience=smd token_hash_prefix=17c3cca6 refresh_family_id=...
```

Expected TokenSmith log when refresh rotation starts happening:

```text
INF Refresh token rotated successfully subject=boot-service audience=smd family_id=... usage_count=1
```

Common TokenSmith failure logs:

```text
WRN Bootstrap token not found client_ip=... token_hash_prefix=17c3cca6
WRN Bootstrap token already consumed (replay attempt) client_ip=... token_hash_prefix=17c3cca6
ERR Refresh token hash mismatch - replay attempt detected family_id=...
ERR Refresh token family is revoked (replay detected via hash lookup) family_id=...
```

Expected caller-service logs depend on the service itself. `pkg/tokenservice` returns errors; it does not emit logs on its own. A service that logs the example flow should show output similar to:

```text
Getting initial service token...
Got token, expires at: 2026-04-14 22:49:10 +0000 UTC
Refreshing token...
Refreshed token, new expiration: 2026-04-14 23:49:10 +0000 UTC
Calling target service...
Successfully called target service!
```

Common caller-service errors when bootstrap wiring is wrong:

```text
missing bootstrap token: set TOKENSMITH_BOOTSTRAP_TOKEN or WithBootstrapToken
bootstrap token exchange failed after 5 attempts: failed to get token: status=400, body={"error":"invalid_grant","error_description":"The provided token is invalid or has already been used"}
failed to get token: status=429, body={"error":"too_many_requests","error_description":"Too many failed token exchange attempts from this address"}
refresh token expired
```

Important:

- `bootstrap-token create` must write policy to the same bootstrap store path used by the running TokenSmith service.
- Treat bootstrap token creation as a strictly local operation to the TokenSmith runtime context.
- For Podman Quadlets (common OpenCHAMI deployment), mint via `podman exec tokensmith ...` so the same mounted store path is used.

Current examples:

- `example/serviceauth` (service token acquisition/refresh)
- `examples/minisvc/main.go` (AuthN + AuthZ middleware wiring)
- `examples/minisvc/policy/` (Casbin model/policy/grouping)

Normative requirements for service principals:

- `docs/authz_contract.md#service-principal-requirements`
- `docs/authz_contract.md#integration-checklist-services`

## 1.4) Endpoint overview

The TokenSmith service currently exposes these user-facing endpoints:

- `GET /health`
- `GET /.well-known/jwks.json`
- `POST /oauth/token`
- `POST /token` (alias for the service-token flow)

See `docs/http-endpoints.md` for request/response formats and failure behavior.

## 1.5) Key material and token-state storage

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
