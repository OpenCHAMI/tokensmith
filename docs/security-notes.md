<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith security & threat model notes

This document captures security-relevant behavior for TokenSmith AuthN (JWT) and AuthZ (Casbin) middleware.

It is a companion to the frozen wire contract:

- `docs/authz-spec.md`

## Threat model (high level)

TokenSmith assumes:

- The service process is running in a trusted environment (e.g., Kubernetes pod).
- Policy files mounted into the service are trusted deploy-time configuration.
- Callers are untrusted and may:
  - send malformed requests
  - replay tokens
  - attempt algorithm confusion or header manipulation
  - attempt to bypass policy via path encoding/normalization tricks

TokenSmith mitigations focus on:

- fail-closed defaults
- deterministic normalization
- minimizing sensitive data exposure in logs and responses

AuthN in `pkg/authn` validates TokenSmith JWTs against the current TokenSmith claim contract. The required claim set includes `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `auth_level`, `auth_factors`, `auth_methods`, `session_id`, `session_exp`, and `auth_events`.

## JWT handling: logging and redaction

- TokenSmith **MUST NOT log raw JWTs**.
- TokenSmith deny responses **MUST NOT echo** Authorization headers or arbitrary JWT claims.
- Principal summaries in logs/deny bodies should contain only:
  - `principal.id`, `principal.type`, and optionally `principal.roles`

If your environment considers roles sensitive, configure TokenSmith to omit role lists in logs.

## Key IDs (`kid`) and key binding

TokenSmith uses RFC 7638 JWK thumbprints (SHA-256, base64url) as JWT `kid` values.

AuthN middleware in `pkg/authn` enforces that:

- JWT header `kid` is present
- `kid` format is RFC 7638-compliant
- key lookup is performed by `kid` (JWKS/static key matching)

Rationale: requiring deterministic key IDs prevents ambiguous static-key fallback and ensures verification binds to the intended signing key.

## Issuer/audience defaults

Per `docs/authz-spec.md`:

- By default TokenSmith JWT validation **requires** and validates:
  - `iss` (issuer)
  - `aud` (audience)

Any opt-out must be explicit in configuration.

Rationale: missing `iss`/`aud` validation is a common misconfiguration that leads to token acceptance from unexpected issuers or for unexpected audiences.

## Algorithm allowlist & confusion risks

JWT validation MUST:

- enforce an **algorithm allowlist** appropriate to the key material (e.g., RS256 for RSA keys)
- reject tokens using `alg=none`
- avoid key confusion between symmetric (HS*) and asymmetric (RS*/ES*) algorithms

If you configure multiple issuers/JWKS sources, ensure they are scoped by issuer/audience as appropriate.

## JWKS caching and availability risks

### What can go wrong

- JWKS endpoint outage can prevent new keys from being fetched.
- Stale caches can accept tokens signed by keys that should have been rotated out.
- Aggressive fail-open behaviors can cause accidental allow.

### TokenSmith behavior

TokenSmith uses **last-known-good caching** with **fail-closed** semantics (see `docs/authz-spec.md`):

- When cached keys exist and refresh fails, TokenSmith continues to use cached keys up to a hard-expiry.
- When no valid cached keys exist and fetch fails, TokenSmith rejects tokens that require those keys.

Operational guidance:

- monitor JWKS fetch errors
- prefer highly-available JWKS endpoints
- ensure your key rotation cadence is compatible with cache TTLs

## Policy loading trust boundary

- Policy files are not signed/verified by TokenSmith in v1.
- Treat the policy directory as trusted configuration (ConfigMap/Secret/volume managed by cluster admins).

If an attacker can modify policy files on disk, they can change authorization decisions.

## Path normalization and policy bypass risks

Path/method style authorization depends on deterministic path normalization.

- TokenSmith must avoid ambiguous decoding.
- Malformed escapes should fail deterministically with a 400 (`reason=bad_request`).

Rationale: inconsistent decoding between routers/middlewares can allow attackers to hit a protected handler while the authorizer evaluates a different path.

## Fail-closed behavior summary

- Policy/model load failures at startup: **fail-fast** (process should not start).
- Runtime engine errors in `ENFORCE`: deny with a stable error response.
- Missing/invalid tokens when authn is required: deny (401) with stable error response.

---

## Local user token security

The `--enable-local-user-mint` flag allows break-glass creation of JWTs without relying on an upstream OIDC provider.

### Trust boundaries

- Local user tokens are signed directly by TokenSmith's private key.
- They do **not** validate against an external OIDC provider.
- The identity (subject, scopes) comes entirely from the local operator, not from a federated identity system.
- Audit trails must record who created each local user token and when.

### Threat model for local user minting

**Assumes:**

- Only trusted local operators can execute `tokensmith user-token create`.
- The TokenSmith private key is protected (e.g., in a Kubernetes secret, encrypted at rest).
- Local token minting is an emergency fallback, not the default operational mode.

**Mitigations:**

- Require explicit `--enable-local-user-mint` flag at startup to activate the feature.
- No local user tokens can be minted if the flag is not set.
- Services should treat local user tokens differently from OIDC-backed tokens (e.g., in audit logs) by inspecting the `auth_methods` or `auth_events` claim.

### Using local user tokens securely

1. **Enable only when needed** — Start TokenSmith with `--enable-local-user-mint` only during bootstrapping or break-glass scenarios.

2. **Limit scope** — Mint tokens with the minimum required scopes:
   ```bash
   tokensmith user-token create \
     --subject "emergency-operator" \
     --scopes "admin"  # only what is needed
   ```

3. **Short lifetimes** — Use `--ttl` to keep tokens valid for the shortest reasonable time:
   ```bash
   tokensmith user-token create \
     --subject "emergency-operator" \
     --scopes "admin" \
     --ttl 15m  # short lifetime for emergency access
   ```

4. **Audit and rotate** — After an emergency:
   - Review logs for all local tokens created
   - Rotate the TokenSmith private key if you suspect compromise
   - Disable `--enable-local-user-mint` in production after bootstrap

5. **Downstream verification** — Service middleware should:
   - Accept TokenSmith JWTs as valid (signature checking handles both OIDC and local tokens)
   - Optionally log or alert on local user tokens (check `auth_methods` claim for "local-user" signals)

### What you should NOT do

- ❌ Do not keep `--enable-local-user-mint` enabled in production unless required for your threat model.
- ❌ Do not mint local user tokens with broad scopes like `"*"` or `"admin"`.
- ❌ Do not embed local token creation in automation scripts; reserve it for manual break-glass scenarios.
- ❌ Do not log the token contents themselves; log only the subject and scopes.

---

## Admin endpoints security

TokenSmith exposes local-only admin endpoints for runtime OIDC provider reconfiguration:

- `GET /admin/oidc/config` — inspect active OIDC configuration
- `POST /admin/oidc/config` — update OIDC provider without restart

### Access control

**Critical:** These endpoints are **loopback-only** (127.0.0.1 or ::1).

- Requests from any other IP address receive **403 Forbidden**.
- This is enforced at the handler level before processing any request.

### Threat model

**Assumes:**

- The TokenSmith process is running in a trusted container/pod, not exposed to untrusted networks.
- Local access (e.g., via `exec`, SSH tunnel, or Kubernetes port-forward) is acceptable for trusted operators.
- Incoming traffic to the service port is filtered to allow only expected clients (e.g., frontend, authorized sidecar).

**Mitigations:**

- Loopback-only gating prevents remote callers from reconfiguring the provider.
- No authentication mechanism is added to admin endpoints (loopback IP is the trust boundary).
- OIDC secrets are never accepted by admin endpoints; they remain env-only.

### Using admin endpoints securely

1. **Restrict port access** — Only allow loopback or trusted local processes to reach TokenSmith's HTTP port (default 8080):
   ```yaml
   # Example: NetworkPolicy in Kubernetes
   kind: NetworkPolicy
   metadata:
     name: tokensmith
   spec:
     ingress:
       - from:
           - namespaceSelector:
               matchLabels:
                 name: backend-services
         ports:
           - protocol: TCP
             port: 8080
   ```

2. **Use tunneling for remote access** — If TokenSmith is on a remote machine, tunnel through `localhost`:
   ```bash
   ssh -L 8080:localhost:8080 user@remote-tokensmith
   # Then locally:
   tokensmith oidc configure \
     --issuer-url "https://..." \
     --client-id "..." \
     --replace-existing
   ```

3. **Audit admin calls** — Log all `/admin/oidc/config` requests (successful and rejected):
   ```bash
   # Monitor TokenSmith logs for admin endpoint activity
   journalctl -u tokensmith | grep "admin/oidc"
   ```

4. **Validate OIDC configuration** — Always use `--dry-run` before applying:
   ```bash
   tokensmith oidc configure \
     --issuer-url "https://new-provider.example.com" \
     --client-id "new-client" \
     --dry-run  # validates without applying
   ```

5. **Provide secret via environment** — The running TokenSmith process must already have `OIDC_CLIENT_SECRET` set:
   ```bash
   # Before starting TokenSmith
   export OIDC_CLIENT_SECRET="<secret>"
   tokensmith serve --oidc-issuer "..." --oidc-client-id "..."

   # Then reconfigure (secret is already known):
   tokensmith oidc configure \
     --issuer-url "https://new-provider.example.com" \
     --client-id "new-client" \
     --replace-existing
   ```

### What you should NOT do

- ❌ Do not expose the admin endpoints to the public internet or untrusted networks.
- ❌ Do not attempt to bypass loopback checking by spoofing X-Forwarded-For headers (TokenSmith does not trust proxy headers for this check).
- ❌ Do not configure OIDC secrets via admin endpoints; use environment variables instead.
- ❌ Do not expose TokenSmith's HTTP port without network segmentation.

### Combined with other controls

Admin endpoints are **local-only by design** but benefit from defense-in-depth:

- Container/process isolation (don't run untrusted code in the same pod)
- NetworkPolicy ingress rules that permit only expected clients
- RBAC on the `exec` or SSH privilege needed to access the container
- Audit logging of admin endpoint calls

See: [Getting started: Break-glass local user tokens](./getting-started.md#14-break-glass-local-user-tokens-emergency-access) for operational workflows that safely use admin endpoints.
