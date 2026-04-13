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
