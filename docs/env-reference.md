<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith environment variable reference

This page lists environment variables currently used by TokenSmith code paths.

## Token service (`tokensmith serve`)

| Variable | Used by | Description |
| --- | --- | --- |
| `OIDC_CLIENT_ID` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-client-id` |
| `OIDC_CLIENT_SECRET` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-client-secret` |
| `TOKENSMITH_BOOTSTRAP_JTI_STORE` | `cmd/tokenservice/serve.go` | Fallback value for `--bootstrap-jti-store` path |

Precedence:

1. Explicit CLI flag value
2. Environment variable fallback

## AuthZ policy loading

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_POLICY_DIR` | `pkg/authz/policyloader` | Preferred path to policy fragment directory |
| `AUTHZ_POLICY_DIR` | `pkg/authz/policyloader` | Alternate path name accepted by policy loader |

If both are set, use one source of truth per deployment to avoid confusion.

## AuthZ decision cache

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_AUTHZ_CACHE_SIZE` | `pkg/authz/authorizer` | Enables decision cache when set to a positive integer |

Notes:

- Cache behavior and policy semantics are still determined by mode and route mapping.
- `policy_version` remains the authoritative hash of effective model/policy/grouping inputs.

## Service-client variables

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_BOOTSTRAP_TOKEN` | `pkg/tokenservice/client.go` | One-time startup bootstrap token redeemed at `POST /service/token` |

## Example-only variables

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_EXAMPLE_JWKS_URL` | `examples/minisvc/main.go` | Optional JWKS URL for the minisvc example |
