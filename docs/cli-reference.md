<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith CLI reference

This page documents the current `tokensmith` command surface in `cmd/tokenservice`.

See also:

- `docs/getting-started.md`
- `docs/http-endpoints.md`
- `docs/env-reference.md`

## Which command should I use?

**I want to...**

- **Start TokenSmith** → Use `tokensmith serve`
- **Generate a default config file** → Use `tokensmith generate-config`
- **Mint a service bootstrap token for RFC 8693 exchange (recommended)** → Use `tokensmith bootstrap-token create`
- **Check current OIDC provider** → Use `tokensmith oidc status`
- **Reconfigure the OIDC provider (no restart)** → Use `tokensmith oidc configure`
- **Mint a break-glass user token (emergency access)** → Use `tokensmith user-token create`

---

## Commands

- `tokensmith generate-config`
- `tokensmith bootstrap-token create`
- `tokensmith oidc status`
- `tokensmith oidc configure`
- `tokensmith serve`
- `tokensmith user-token create`

Global flag:

- `--config` path to a JSON config file

## `tokensmith generate-config`

Generates a default configuration JSON file.

Example:

```bash
tokensmith generate-config --config ./config.json
```

Prefer passing `--config` explicitly.

## `tokensmith serve`

Starts the TokenSmith service.

### Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--issuer` | Token issuer identifier | `http://tokensmith:8080` |
| `--port` | HTTP server port | `8080` |
| `--cluster-id` | Cluster identifier | `cl-F00F00F00` |
| `--openchami-id` | OpenCHAMI instance identifier | `oc-F00F00F00` |
| `--oidc-issuer` | OIDC issuer URL | `http://hydra:4444` |
| `--oidc-client-id` | OIDC client ID, or `OIDC_CLIENT_ID` | `""` |
| `--oidc-client-secret` | OIDC client secret, or `OIDC_CLIENT_SECRET` | `""` |
| `--key-file` | Existing private key path | `""` |
| `--key-dir` | Directory where generated keys are saved when `--key-file` is not set | `""` |
| `--enable-local-user-mint` | Enable break-glass local user token creation endpoint | `false` |
| `--rfc8693-bootstrap-store` | Path to the bootstrap token policy store, or `TOKENSMITH_RFC8693_BOOTSTRAP_STORE` | `./data/bootstrap-tokens` |
| `--rfc8693-refresh-store` | Path to the refresh token family store, or `TOKENSMITH_RFC8693_REFRESH_STORE` | `./data/refresh-tokens` |
| `--non-enforcing` | Skip strict validation checks and only log errors | `false` |
| `--config` | Path to JSON config file | `""` |

### Key behavior

- If `--key-file` is set, TokenSmith loads that private key.
- If `--key-file` is not set, TokenSmith generates an RSA keypair and writes it to `--key-dir` as `private.pem` and `public.pem`.
- If `--oidc-client-id` or `--oidc-client-secret` are omitted, TokenSmith reads `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`.
- If RFC 8693 store flags are omitted, TokenSmith falls back to environment variables and then the defaults shown above.

### Minimal run example

```bash
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --oidc-issuer https://issuer.example \
  --oidc-client-id your-client-id \
  --rfc8693-bootstrap-store ./data/bootstrap-tokens \
  --rfc8693-refresh-store ./data/refresh-tokens
```

### User-facing endpoints

The `serve` command exposes:

- `GET /health`
- `GET /.well-known/jwks.json`
- `POST /oauth/token`
- `POST /token` (alias for the service-token flow)

See `docs/http-endpoints.md` for request and response formats.

## `tokensmith bootstrap-token create` (recommended for RFC 8693)

Creates an opaque one-time bootstrap token and stores server-side policy metadata used by `POST /oauth/token`.

This is the recommended command for current RFC 8693 bootstrap exchange flows.

### Important

- The token is only usable by a TokenSmith instance that can read the same bootstrap policy store path.
- Set `--bootstrap-store` to the same path used by the running TokenSmith service (`--rfc8693-bootstrap-store`).
- If omitted, `bootstrap-token create` uses a temporary local directory, which is usually not shared with the running service.
- Treat this as a strictly local operation to the TokenSmith runtime context.
- For Podman Quadlets, run `tokensmith bootstrap-token create` via `podman exec` in the TokenSmith container namespace.
- Runtime behavior: when `/oauth/token` does not find a bootstrap policy in memory, TokenSmith attempts a one-file disk lookup (`<token-hash>.json`) and caches the result for subsequent requests.

### Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--subject` | Caller service identity | `""` (required) |
| `--audience` | Target service audience | `""` (required) |
| `--scopes` | Comma- or space-separated scopes | `""` |
| `--ttl` | Bootstrap token lifetime (min 1m, max 1h) | `10m` |
| `--refresh-ttl` | Refresh family max lifetime (min 1h, max 30d) | `24h` |
| `--binding-identifier` | Optional audit/binding context | `""` |
| `--output-format` | Output format (`text` or `json`) | `text` |
| `--bootstrap-store` | Bootstrap policy store path (must match server store) | temp directory |

### Example

```bash
# Start TokenSmith with explicit durable stores
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --rfc8693-bootstrap-store ./data/bootstrap-tokens \
  --rfc8693-refresh-store ./data/refresh-tokens

# Mint opaque bootstrap token against the same bootstrap store path
BOOTSTRAP_TOKEN=$(tokensmith bootstrap-token create \
  --subject example-service-1 \
  --audience metadata-service \
  --scopes "read" \
  --ttl 10m \
  --refresh-ttl 24h \
  --bootstrap-store ./data/bootstrap-tokens \
  --output-format json | jq -r '.bootstrap_token')

# Podman Quadlet pattern (recommended for OpenCHAMI)
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

### Container-first operational workflow

This is the clearest production pattern when TokenSmith runs in a container and caller services need one bootstrap token each.

#### 1. Start TokenSmith with bootstrap and refresh stores configured

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

The important part is that TokenSmith starts with a durable bootstrap store and refresh store. Those same paths must be used when creating bootstrap tokens.

#### 2. Exec into the TokenSmith container and mint one token per caller service

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

Use one distinct bootstrap token per caller service. Do not reuse a single bootstrap token across services.

Recommended mapping:

- `--subject`: the caller service identity
- `--audience`: the downstream service that caller will access
- `--scopes`: the scopes TokenSmith should embed in the issued JWT

#### 3. Pass the matching bootstrap token to each caller service

Each caller service needs:

- `TOKENSMITH_URL`: how it reaches TokenSmith
- `TOKENSMITH_BOOTSTRAP_TOKEN`: the token minted specifically for that caller

Example:

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

If your service uses `pkg/tokenservice`, that bootstrap token is exchanged once at runtime at `POST /oauth/token`. After that, the service uses the returned refresh token family to keep getting fresh JWTs without reusing the bootstrap token.

#### 4. What logs to expect

In TokenSmith, a successful first-time bootstrap exchange produces a log like:

```text
INF Bootstrap token successfully exchanged for service token subject=boot-service audience=smd token_hash_prefix=17c3cca6 refresh_family_id=...
```

Later refreshes from that same service produce logs like:

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

In the caller service, expected logs depend on whether the service logs `pkg/tokenservice` errors itself. The library does not emit logs on its own; it returns errors to the caller.

For the example client in `example/serviceauth`, the normal startup flow looks like:

```text
Getting initial service token...
Got token, expires at: 2026-04-14 22:49:10 +0000 UTC
Refreshing token...
Refreshed token, new expiration: 2026-04-14 23:49:10 +0000 UTC
Calling target service...
Successfully called target service!
```

If the bootstrap token is missing or wrong, a caller service using `pkg/tokenservice` typically surfaces errors like:

```text
missing bootstrap token: set TOKENSMITH_BOOTSTRAP_TOKEN or WithBootstrapToken
bootstrap token exchange failed after 5 attempts: failed to get token: status=400, body={"error":"invalid_grant","error_description":"The provided token is invalid or has already been used"}
failed to get token: status=429, body={"error":"too_many_requests","error_description":"Too many failed token exchange attempts from this address"}
refresh token expired
```

If you are integrating `pkg/tokenservice` into your own service, log the return values from `Initialize()` and `RefreshTokenIfNeeded()`, and expose `client.Stats()` in diagnostics so operators can see the last refresh error and token state.

### What the token is for

Opaque bootstrap tokens are one-time startup credentials exchanged at `POST /oauth/token` using the RFC 8693 bootstrap-token request shape documented in `docs/http-endpoints.md`.

## `tokensmith oidc status`

Shows active single-provider OIDC runtime status from a running local TokenSmith instance.

Flags:

- `--url` TokenSmith base URL (default `http://127.0.0.1:8080`)

Example:

```bash
tokensmith oidc status --url http://127.0.0.1:8080
```

## `tokensmith oidc configure`

Configures the active single OIDC provider on a running local TokenSmith instance without restart.

Flags:

- `--url` TokenSmith base URL (default `http://127.0.0.1:8080`)
- `--issuer-url` OIDC issuer URL (required)
- `--client-id` OIDC client ID (required)
- `--replace-existing` required when replacing an already configured provider
- `--dry-run` validates and reports create/replace result without applying

Notes:

- This is a local-only operation; the service rejects non-loopback calls.
- OIDC client secret is not accepted by this command and is never written to config.
- The running service must already have `OIDC_CLIENT_SECRET` configured.

Example:

```bash
tokensmith oidc configure \
  --url http://127.0.0.1:8080 \
  --issuer-url https://issuer.example \
  --client-id tokensmith-client
```

Replace existing provider:

```bash
tokensmith oidc configure \
  --url http://127.0.0.1:8080 \
  --issuer-url https://new-issuer.example \
  --client-id tokensmith-client \
  --replace-existing
```

## `tokensmith user-token create`

Creates a local user JWT for break-glass/no-upstream-OIDC scenarios.

Required flags:

- `--enable-local-user-mint`
- `--key-file`
- `--subject`
- `--scopes`

Important:

- This path is intentionally explicit and should not be the normal operational mode.
- Tokens are signed with the provided private key and include user-provided scopes.

Example:

```bash
tokensmith user-token create \
  --enable-local-user-mint \
  --key-file ./keys/private.pem \
  --subject operator@example \
  --audience openchami \
  --scopes read,write \
  --ttl 1h
```

## Configuration file schema

The `--config` file currently supports `groupScopes`:

```json
{
  "groupScopes": {
    "admin": ["admin", "write", "read"],
    "operator": ["write", "read"],
    "viewer": ["read"],
    "user": ["read"]
  }
}
```

Generate a baseline file with:

```bash
tokensmith generate-config --config ./config.json
```
