<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Keycloak token exchange for OpenCHAMI APIs

Use this flow when you already have a CSM or Keycloak bearer token and need a TokenSmith JWT accepted by OpenCHAMI services.

This is not the bootstrap-token flow. Keycloak tokens go to `POST /oauth/exchange`. Bootstrap and refresh tokens go to `POST /oauth/token`.

## 1) Configure TokenSmith

TokenSmith needs an OIDC issuer, client ID, client secret, and claim policy. For CSM Keycloak tokens, select the explicit CSM policy:

```bash
export OIDC_CLIENT_ID="tokensmith"
export OIDC_CLIENT_SECRET="<keycloak-client-secret>"
export TOKENSMITH_OIDC_CLAIM_POLICY="csm-keycloak"
export TOKENSMITH_OIDC_CA="/etc/openchami/tls/keycloak-ca.pem"

tokensmith serve \
  --config ./config.json \
  --key-dir ./keys \
  --issuer http://localhost:8080 \
  --oidc-issuer https://keycloak.example/realms/csm
```

Set `TOKENSMITH_OIDC_CA` or `--oidc-ca` when Keycloak uses a private CA. This bundle is used only for outbound TLS validation when TokenSmith calls OIDC discovery, JWKS, and introspection endpoints. Do not replace this with `--service-identity-ca`; that option trusts inbound service-identity mTLS client certificates.

The default claim policy is `enriched`. It preserves the stricter TokenSmith claim contract and expects upstream tokens to include `auth_level`, `auth_factors`, `auth_methods`, `session_id`, `session_exp`, and `auth_events`.

The `csm-keycloak` policy accepts standard Keycloak/OIDC claim names where they provide the same evidence:

| TokenSmith claim | CSM Keycloak source |
| --- | --- |
| `auth_level` | `auth_level`, else `acr` only when it is already `IAL1`, `IAL2`, or `IAL3` |
| `auth_methods` | `auth_methods`, else recognized `amr` values: password, OTP, or hardware families |
| `auth_factors` | `auth_factors`, else the number of distinct recognized `auth_methods` |
| `session_id` | `session_id`, else `sid` |
| `session_exp` | `session_exp`, else `exp` |
| `auth_events` | `auth_events` |

TokenSmith still fails closed when the mapped claims cannot produce a valid TokenSmith JWT. For example, a token with only one authentication method cannot satisfy the default downstream `auth_factors >= 2` requirement, and numeric `acr` values are not treated as NIST IAL values. If your CSM Keycloak token does not include `auth_events`, add a Keycloak protocol mapper for that claim or use the default `enriched` policy with TokenSmith-native claims.

## 2) Exchange the Keycloak token

```bash
export TOKENSMITH_URL="http://localhost:8080"
export KEYCLOAK_TOKEN="<csm-or-keycloak-access-token>"

TOKENSMITH_TOKEN=$(curl -fsS -X POST "$TOKENSMITH_URL/oauth/exchange" \
  -H "Authorization: Bearer $KEYCLOAK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scope":["read"],"target_service":"smd"}' | jq -r '.access_token')
```

`scope` and `target_service` are optional request constraints. Requested scopes must be a subset of scopes derived from the token's mapped groups. If `target_service` is set, TokenSmith writes it as the JWT audience.

## 3) Use the TokenSmith JWT

```bash
curl -fsS "https://openchami.example/apis/smd/hsm/v2/State/Components" \
  -H "Authorization: Bearer $TOKENSMITH_TOKEN"
```

## Troubleshooting

If exchange fails, check TokenSmith logs for `audit_event=token_exchange_failed`.

Common `failure_category` values:

| Category | Meaning |
| --- | --- |
| `upstream_unavailable` | TokenSmith could not reach the OIDC provider or introspection endpoint. |
| `upstream_rejected` | The provider returned a non-200 introspection response. |
| `invalid_response` | Provider metadata, JWKS, or introspection JSON was malformed. |
| `missing_claim` | The token lacked required claim names for the selected claim policy. |
| `invalid_claim` | A present or mapped claim could not satisfy TokenSmith's JWT contract. |
| `inactive_token` | The provider reported the token as inactive. |

TokenSmith logs missing claim names, not claim values. It does not log bearer tokens, bootstrap tokens, refresh tokens, client secrets, Authorization headers, or raw upstream responses.

## Endpoint quick reference

| Use case | Endpoint | Credential |
| --- | --- | --- |
| Exchange CSM/Keycloak bearer token | `POST /oauth/exchange` | `Authorization: Bearer <keycloak-token>` |
| Redeem one-time service bootstrap token | `POST /oauth/token` | form `subject_token=<bootstrap-token>` |
| Rotate refresh token | `POST /oauth/token` | form `refresh_token=<refresh-token>` |
