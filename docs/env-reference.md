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
| `TOKENSMITH_RFC8693_BOOTSTRAP_STORE` | `cmd/tokenservice/serve.go` | Fallback value for `--rfc8693-bootstrap-store`; default `./data/bootstrap-tokens` |
| `TOKENSMITH_RFC8693_REFRESH_STORE` | `cmd/tokenservice/serve.go` | Fallback value for `--rfc8693-refresh-store`; default `./data/refresh-tokens` |

OIDC runtime configuration notes:

- `OIDC_CLIENT_SECRET` is environment-only and is not persisted by OIDC runtime configure workflows.
- `tokensmith oidc configure` updates issuer/client-id only and expects the running service to already have `OIDC_CLIENT_SECRET` set.

Precedence for these values:

1. explicit CLI flag value
2. environment variable fallback
3. built-in default

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

- cache behavior and policy semantics are still determined by mode and route mapping
- `policy_version` remains the authoritative hash of effective model/policy/grouping inputs

## Service-client variables

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_URL` | Consumer services using `pkg/tokenservice` | Base URL of the TokenSmith service, used to call `POST /oauth/token` |
| `TOKENSMITH_BOOTSTRAP_TOKEN` | `pkg/tokenservice/client.go` | One-time startup bootstrap token redeemed at `POST /oauth/token` |
| `TOKENSMITH_TARGET_SERVICE` | Consumer service configuration | Common config convention for intended audience service |
| `TOKENSMITH_SCOPES` | Consumer service configuration | Common config convention for intended scopes |
| `TOKENSMITH_REFRESH_SKEW_SEC` | Consumer service configuration | Common config convention for refresh lead time |

Notes:

- only `TOKENSMITH_BOOTSTRAP_TOKEN` is read directly by current `pkg/tokenservice/client.go` defaults
- current `ServiceClient` uses RFC 8693 bootstrap and refresh form fields only
- target service and scopes are currently authoritative on the server side from bootstrap-token policy and refresh-token family state
- many consumer services still map `TOKENSMITH_TARGET_SERVICE`, `TOKENSMITH_SCOPES`, and `TOKENSMITH_REFRESH_SKEW_SEC` into explicit client options for local configuration consistency

## Example-only variables

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_EXAMPLE_JWKS_URL` | `examples/minisvc/main.go` | Optional direct JWKS URL for the minisvc example |
