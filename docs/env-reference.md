<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith environment variable reference

This page lists environment variables currently used by TokenSmith code paths.

## Token service (`tokensmith serve`)

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_ISSUER` | `cmd/tokenservice/serve.go` | Fallback value for `--issuer`; required, no built-in default |
| `TOKENSMITH_OIDC_PROVIDER` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-issuer` (note the name mismatch); required, no built-in default |
| `TOKENSMITH_PORT` | `cmd/tokenservice/serve.go` | Fallback value for `--port`; default `8080` |
| `TOKENSMITH_CLUSTER_ID` | `cmd/tokenservice/serve.go` | Fallback value for `--cluster-id`; default `cl-F00F00F00` |
| `TOKENSMITH_OPENCHAMI_ID` | `cmd/tokenservice/serve.go` | Fallback value for `--openchami-id`; default `oc-F00F00F00` |
| `TOKENSMITH_CONFIG` | `cmd/tokenservice/serve.go` | Fallback value for `--config`; empty means built-in `groupScopes` |
| `TOKENSMITH_KEY_DIR` | `cmd/tokenservice/serve.go` | Fallback value for `--key-dir`; empty writes key files to the working directory |
| `OIDC_CLIENT_ID` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-client-id` |
| `OIDC_CLIENT_SECRET` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-client-secret` |
| `TOKENSMITH_OIDC_INTROSPECTION_ENDPOINT` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-introspection-endpoint`; overrides provider discovery for token introspection |
| `TOKENSMITH_OIDC_CLAIM_POLICY` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-claim-policy`; valid values: `enriched`, `csm-keycloak` |
| `TOKENSMITH_OIDC_CA` | `cmd/tokenservice/serve.go` | Fallback value for `--oidc-ca` (PEM CA bundle for upstream OIDC TLS validation) |
| `TOKENSMITH_MAX_EXCHANGE_SESSION_LIFETIME` | `cmd/tokenservice/serve.go` | Fallback value for `--max-exchange-session-lifetime`; Go duration such as `24h` or `168h` |
| `TOKENSMITH_RFC8693_BOOTSTRAP_STORE` | `cmd/tokenservice/serve.go` | Fallback value for `--rfc8693-bootstrap-store`; default `./data/bootstrap-tokens` |
| `TOKENSMITH_RFC8693_REFRESH_STORE` | `cmd/tokenservice/serve.go` | Fallback value for `--rfc8693-refresh-store`; default `./data/refresh-tokens` |
| `TOKENSMITH_SERVICE_IDENTITY_CA` | `cmd/tokenservice/serve.go` | Fallback value for `--service-identity-ca` (PEM CA bundle for inbound mTLS client cert trust) |
| `TOKENSMITH_TLS_CERT_FILE` | `cmd/tokenservice/serve.go` | Fallback value for `--tls-cert-file` (TokenSmith HTTPS server certificate) |
| `TOKENSMITH_TLS_KEY_FILE` | `cmd/tokenservice/serve.go` | Fallback value for `--tls-key-file` (TokenSmith HTTPS server private key) |

OIDC runtime configuration notes:

- `OIDC_CLIENT_SECRET` is environment-only and is not persisted by OIDC runtime configure workflows.
- `tokensmith oidc configure` updates issuer/client-id and, when supplied, claim policy. It expects the running service to already have `OIDC_CLIENT_SECRET` set.
- `TOKENSMITH_OIDC_INTROSPECTION_ENDPOINT` is optional. When empty, TokenSmith uses `token_introspection_endpoint` from discovery metadata, then `introspection_endpoint`.
- `TOKENSMITH_OIDC_CLAIM_POLICY` defaults to `enriched`; use `csm-keycloak` only for CSM Keycloak bearer-token exchange.
- `TOKENSMITH_OIDC_CA` affects outbound HTTPS validation for OIDC discovery, JWKS, and introspection only. It is separate from `TOKENSMITH_SERVICE_IDENTITY_CA`, which trusts inbound service-identity client certificates.
- `TOKENSMITH_MAX_EXCHANGE_SESSION_LIFETIME` defaults to `24h`. Longer values are explicit risk acceptance for longer generated TokenSmith tokens; exchanged tokens are still capped by upstream `exp` and `session_exp`.

Precedence for these values:

1. explicit CLI flag value
2. environment variable fallback
3. JSON config file value, where supported
4. built-in default

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
| `TOKENSMITH_SERVICE_IDENTITY_CERT` | `pkg/tokenservice/client.go` | Optional path to service mTLS client certificate used with `POST /service-identity/session` |
| `TOKENSMITH_SERVICE_IDENTITY_KEY` | `pkg/tokenservice/client.go` | Optional path to service mTLS client private key used with `POST /service-identity/session` |
| `TOKENSMITH_TARGET_SERVICE` | Consumer service configuration | Common config convention for intended audience service |
| `TOKENSMITH_SCOPES` | Consumer service configuration | Common config convention for intended scopes |
| `TOKENSMITH_REFRESH_SKEW_SEC` | Consumer service configuration | Common config convention for refresh lead time |

Notes:

- `ServiceClient` prefers `TOKENSMITH_SERVICE_IDENTITY_CERT` + `TOKENSMITH_SERVICE_IDENTITY_KEY` when both files are readable, then falls back to `TOKENSMITH_BOOTSTRAP_TOKEN`
- bootstrap and refresh paths still use RFC 8693 form fields against `POST /oauth/token`
- target service and scopes are currently authoritative on the server side from bootstrap-token policy and refresh-token family state
- many consumer services still map `TOKENSMITH_TARGET_SERVICE`, `TOKENSMITH_SCOPES`, and `TOKENSMITH_REFRESH_SKEW_SEC` into explicit client options for local configuration consistency

## Example-only variables

| Variable | Used by | Description |
| --- | --- | --- |
| `TOKENSMITH_EXAMPLE_JWKS_URL` | `examples/minisvc/main.go` | Optional direct JWKS URL for the minisvc example |
