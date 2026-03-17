<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith CLI reference

This page documents the current `tokensmith` command surface in `cmd/tokenservice`.

## Commands

- `tokensmith generate-config`
- `tokensmith serve`

Global flag:

- `--config` path to a JSON config file

## `tokensmith generate-config`

Generates a default configuration JSON file.

Example:

```bash
tokensmith generate-config --config ./config.json
```

If `--config` is omitted, command behavior depends on your shell invocation path. Prefer passing `--config` explicitly.

## `tokensmith serve`

Starts the token service.

### Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--issuer` | Token issuer identifier | `http://tokensmith:8080` |
| `--port` | HTTP server port | `8080` |
| `--cluster-id` | Cluster identifier | `cl-F00F00F00` |
| `--openchami-id` | OpenCHAMI instance identifier | `oc-F00F00F00` |
| `--oidc-issuer` | OIDC issuer URL | `http://hydra:4444` |
| `--oidc-client-id` | OIDC client ID (or `OIDC_CLIENT_ID`) | `""` |
| `--oidc-client-secret` | OIDC client secret (or `OIDC_CLIENT_SECRET`) | `""` |
| `--key-file` | Existing private key path | `""` |
| `--key-dir` | Directory where generated keys are saved | `""` |
| `--non-enforcing` | Skip strict validation checks and log errors | `false` |
| `--config` | Path to JSON config file | `""` |

### Key behavior

- If `--key-file` is set, TokenSmith loads that private key.
- If `--key-file` is not set, TokenSmith generates RSA keys and writes them to `--key-dir` as `private.pem` and `public.pem`.
- If `--oidc-client-id` / `--oidc-client-secret` are omitted, TokenSmith reads `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET`.

### Minimal run example

```bash
tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --oidc-issuer https://issuer.example \
  --oidc-client-id your-client-id
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
