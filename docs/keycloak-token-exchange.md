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
export OIDC_CLIENT_ID="openchami-tokensmith"
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

The `csm-keycloak` policy accepts CSM Keycloak user and service-account tokens. TokenSmith still requires the upstream token issuer to match `--oidc-issuer`. The upstream token does not need `aud` to equal the TokenSmith client; Keycloak service-account tokens commonly use `aud=account`. Instead, TokenSmith accepts the token when any of these identify the configured client ID:

- `aud`
- `azp`
- `client_id`

For the observed CSM service-account shape, set `OIDC_CLIENT_ID` or `--oidc-client-id` to the Keycloak client ID, for example `openchami-tokensmith`.

The policy maps claims this way:

| TokenSmith claim | CSM Keycloak source |
| --- | --- |
| `aud` | upstream `aud`; can be overridden with request `target_service` |
| `sub` | introspection `username`, else `preferred_username`, else `sub` |
| `auth_level` | `auth_level`, else any non-empty `acr`, else `keycloak` |
| `auth_methods` | `auth_methods`, else recognized `amr` values, else `keycloak` and `client_credentials` |
| `auth_factors` | `auth_factors`, else distinct mapped factor categories, minimum `2` for TokenSmith compatibility |
| `session_id` | `session_id`, else `sid`, else `jti`, else `client_id`, else `azp` |
| `session_exp` | `session_exp`, else `exp` |
| `auth_events` | `auth_events`, else `token_exchange` |

This policy is intentionally compatibility-focused. It lets TokenSmith convert a Keycloak service-account token into the stricter TokenSmith JWT shape that OpenCHAMI APIs already validate.

> [!warning]
> When Keycloak omits `amr` and `auth_factors`, `csm-keycloak` fills TokenSmith compatibility fields so the downstream JWT is structurally valid. These fallback values indicate that Keycloak accepted a client-credentials token; they must not be interpreted by downstream services as proof that a human completed MFA.

### Decoded token checklist

Before exchanging, inspect the token shape locally:

```bash
printf '%s' "$KEYCLOAK_TOKEN" \
  | jq -R 'split(".") | .[1] | @base64d | fromjson | {iss,aud,azp,client_id,sub,preferred_username,acr,amr,sid,jti,exp,scope,realm_access,resource_access}'
```

For a CSM Keycloak service-account token, the minimal expected shape is:

```json
{
  "iss": "https://keycloak.example/realms/csm",
  "aud": "account",
  "azp": "openchami-tokensmith",
  "client_id": "openchami-tokensmith",
  "sub": "<uuid>",
  "preferred_username": "service-account-openchami-tokensmith",
  "acr": "1",
  "jti": "<token-id>",
  "exp": 1787948769
}
```

Checklist:

- `iss` must exactly match `--oidc-issuer`.
- At least one of `aud`, `azp`, or `client_id` must match `--oidc-client-id`.
- `exp` must be present and in the future.
- `preferred_username` or `sub` should identify the exchanged principal.
- `groups` is optional. If absent, TokenSmith mints a valid token with no OpenCHAMI scopes unless you request `target_service` only.
- Requested `scope` values must be derived from mapped groups; a token with no groups cannot request `read` or `write` scopes.

For user tokens, add Keycloak protocol mappers when you want richer TokenSmith claims:

| Desired claim | Keycloak mapper source |
| --- | --- |
| `groups` | group membership mapper |
| `auth_events` | custom claim mapper or upstream authentication event source |
| `sid` | built-in session ID claim if available |
| `amr` | authentication method reference mapper if available |

## 2) Exchange the Keycloak token

```bash
export TOKENSMITH_URL="http://localhost:8080"
export KEYCLOAK_TOKEN="<csm-or-keycloak-access-token>"

TOKENSMITH_TOKEN=$(curl -fsS -X POST "$TOKENSMITH_URL/oauth/exchange" \
  -H "Authorization: Bearer $KEYCLOAK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_service":"smd"}' | jq -r '.access_token')
```

`scope` and `target_service` are optional request constraints. Requested scopes must be a subset of scopes derived from the token's mapped groups. If the Keycloak token has no mapped groups, omit `scope` or configure group mapping first. If `target_service` is set, TokenSmith writes it as the JWT audience.

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
