<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith HTTP endpoints

This page documents the user-facing HTTP endpoints exposed by the TokenSmith service.

## Public endpoints

### `GET /health`

Returns a basic JSON health response for the running TokenSmith instance.

Current response fields include:

- `status`
- `service`
- `issuer`
- `cluster_id`
- `openchami_id`
- `oidc_issuer`

Example:

```bash
curl -s http://localhost:8080/health | jq
```

### `GET /.well-known/jwks.json`

Returns the active public signing keys in JWKS format.

Use this endpoint to configure JWT verifiers for TokenSmith-issued tokens.

Current behavior:

- response content type is `application/json`
- response body contains a standard `keys` array
- RSA keys include `kty`, `use`, `alg`, `kid`, `n`, and `e`

Example:

```bash
curl -s http://localhost:8080/.well-known/jwks.json | jq
```

Important:

- TokenSmith currently exposes a direct JWKS endpoint
- TokenSmith does not currently publish its own OIDC discovery document at `/.well-known/openid-configuration`
- Configure verifiers with the direct JWKS URL unless you are using a separate discovery layer

## Service-token endpoints

### `POST /oauth/token`

Canonical token endpoint for the service-to-service bootstrap and refresh flows.

### `POST /token`

Compatibility alias for the same RFC 8693 / RFC 6749 token handling used by the service-token flow.

For new integrations, prefer `POST /oauth/token`.

## Bootstrap token exchange

Exchange a one-time bootstrap token for an access token and refresh token.

Request format:

- method: `POST`
- content type: `application/x-www-form-urlencoded`

Required form fields:

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
- `subject_token=<bootstrap-token>`
- `subject_token_type=urn:openchami:params:oauth:token-type:bootstrap-token`

Example:

```bash
curl -s http://localhost:8080/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token=<bootstrap-token>' \
  --data-urlencode 'subject_token_type=urn:openchami:params:oauth:token-type:bootstrap-token'
```

Successful response shape:

```json
{
  "access_token": "<service-jwt>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque-refresh-token>",
  "refresh_expires_in": 86400,
  "scope": "read write",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access-token"
}
```

Notes:

- audience and scopes are determined server-side from the bootstrap token policy
- bootstrap tokens are one-time use
- reusing a consumed token fails with `invalid_grant`

## Refresh token grant

Rotate a refresh token and receive a new access token plus a new refresh token.

Request format:

- method: `POST`
- content type: `application/x-www-form-urlencoded`

Required form fields:

- `grant_type=refresh_token`
- `refresh_token=<opaque-refresh-token>`

Example:

```bash
curl -s http://localhost:8080/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'refresh_token=<opaque-refresh-token>'
```

Notes:

- refresh tokens are rotated on every successful use
- replaying an old refresh token revokes the entire token family
- expired or revoked refresh tokens fail with `invalid_grant`

## Error responses

TokenSmith returns OAuth-style JSON error responses:

```json
{
  "error": "invalid_grant",
  "error_description": "The provided token is invalid or has already been used"
}
```

Observed error codes include:

- `invalid_request`
- `unsupported_grant_type`
- `invalid_grant`
- `too_many_requests`
- `server_error`

Observed status codes include:

- `200 OK`
- `400 Bad Request`
- `405 Method Not Allowed`
- `429 Too Many Requests`
- `500 Internal Server Error`

## Security-relevant behavior

### Bootstrap token replay protection

Bootstrap tokens are single-use. Once redeemed, the server marks the bootstrap policy as consumed and rejects future reuse attempts.

### Failed-attempt throttling

TokenSmith rate limits failed bootstrap exchanges per client IP.

Current behavior:

- 5 failed bootstrap exchanges per client IP
- 60 second window
- exceeding the threshold returns `429 too_many_requests`

### Refresh token family revocation

Refresh tokens are tracked as token families.

If an old rotated refresh token is replayed, the family is revoked and future refresh attempts for that family are rejected.
