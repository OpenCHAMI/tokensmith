<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith claim reference

This document describes all claims available in TokenSmith JWTs and how they are used.

## Standard JWT claims (RFC 7519)

These claims are present in every TokenSmith JWT and follow the JWT standard.

| Claim | Type | Description | Example | Required |
|-------|------|-------------|---------|----------|
| `iss` | string | Issuer: identifies who issued the token | `"https://tokensmith.example.com"` | Yes |
| `sub` | string | Subject: the principal this token represents | `"user123"` or `"admin@example.com"` | Yes |
| `aud` | string or array | Audience: intended recipients of the token | `"service-a"` or `["service-a", "service-b"]` | No |
| `exp` | number | Expiration time (Unix timestamp in seconds) | `1703088000` | Yes |
| `nbf` | number | Not Before: earliest time token is valid (Unix timestamp) | `1703080000` | Yes |
| `iat` | number | Issued At: when token was created (Unix timestamp) | `1703084000` | Yes |
| `jti` | string | JWT ID: unique identifier for this token | `"abc123def456"` | No |

### Example standard claims

```json
{
  "iss": "https://tokensmith.example.com",
  "sub": "user123",
  "aud": ["service-a", "service-b"],
  "exp": 1703088000,
  "nbf": 1703080000,
  "iat": 1703084000,
  "jti": "abc123def456"
}
```

---

## OpenID Connect (OIDC) claims

These claims come from the upstream OIDC provider (if using OIDC flow) or are set by TokenSmith when minting local user tokens.

| Claim | Type | Description | Example | Source |
|-------|------|-------------|---------|--------|
| `name` | string | End-user's full name | `"John Doe"` | OIDC provider |
| `email` | string | End-user's email address | `"john@example.com"` | OIDC provider |
| `email_verified` | boolean | Is the email verified by the provider? | `true` | OIDC provider |
| `nonce` | string | Replay attack mitigation value | `"n-0S6_WzA2Mj"` | OIDC provider |
| `auth_time` | number | When user authenticated (Unix timestamp) | `1703084000` | OIDC provider |

### Example OIDC claims

```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true,
  "auth_time": 1703084000,
  "nonce": "n-0S6_WzA2Mj"
}
```

---

## Authentication context claims (NIST SP 800-63B)

These claims describe how the user authenticated and their assurance level. Used for policy enforcement.

| Claim | Type | Description | Example | Notes |
|-------|------|-------------|---------|-------|
| `amr` | array | Authentication Methods used | `["pwd", "otp"]` | From OIDC provider |
| `acr` | string | Authentication Context Class Reference | `"urn:mace:incommon:iap:silver"` | From OIDC provider |
| `auth_level` | string | Identity Assurance Level (IAL) | `"IAL1"`, `"IAL2"`, `"IAL3"` | From OIDC provider |
| `auth_factors` | number | Number of distinct auth factors | `1` or `2` | Counted by TokenSmith |
| `auth_methods` | array | Specific authentication methods used | `["password", "webauthn"]` | Set by TokenSmith |
| `auth_events` | array | History of authentication events | `["login", "mfa_verify"]` | Set by TokenSmith |

### Example authentication context claims

```json
{
  "amr": ["pwd", "otp"],
  "acr": "urn:mace:incommon:iap:silver",
  "auth_level": "IAL2",
  "auth_factors": 2,
  "auth_methods": ["password", "totp"],
  "auth_events": ["login", "mfa_complete"]
}
```

### Using auth_level for policy enforcement

```go
// Example: Require IAL2 for sensitive operations
func authorizeByAssurance(ctx context.Context) error {
    claims, err := authn.VerifiedClaimsFromContext(ctx)
    if err != nil {
        return err
    }

    if claims.AuthLevel != "IAL2" && claims.AuthLevel != "IAL3" {
        return fmt.Errorf("insufficient assurance level: %s", claims.AuthLevel)
    }
    return nil
}
```

---

## Scope and authorization claims

These claims represent permissions granted to the token holder.

| Claim | Type | Description | Example |
|-------|------|-------------|---------|
| `scope` | array | OAuth scopes granted | `["read", "write", "admin"]` |

### Example scope claims

```json
{
  "scope": ["users:read", "users:write", "admin:read"]
}
```

### Using scopes for authorization

```go
// Example: Check for required scope
func requireScope(ctx context.Context, required string) error {
    claims, err := authn.VerifiedClaimsFromContext(ctx)
    if err != nil {
        return err
    }

    for _, scope := range claims.Scope {
        if scope == required {
            return nil
        }
    }
    return fmt.Errorf("missing required scope: %s", required)
}
```

---

## Session claims

These claims manage token and session lifecycle.

| Claim | Type | Description | Example |
|-------|------|-------------|---------|
| `session_id` | string | Unique session identifier | `"sess_abc123"` |
| `session_exp` | number | Session expiration (Unix timestamp) | `1703084000` |

### Example session claims

```json
{
  "session_id": "sess_abc123xyz789",
  "session_exp": 1703084000
}
```

### Using session expiration

```go
// Example: Enforce max session duration
func checkSessionExpiry(ctx context.Context) error {
    claims, err := authn.VerifiedClaimsFromContext(ctx)
    if err != nil {
        return err
    }

    sessionExpiry := time.Unix(claims.SessionExp, 0)
    if time.Now().After(sessionExpiry) {
        return errors.New("session expired")
    }
    return nil
}
```

---

## OpenCHAMI-specific claims

These claims are specific to the OpenCHAMI project and environment.

| Claim | Type | Description | Example |
|-------|------|-------------|---------|
| `cluster_id` | string | OpenCHAMI cluster identifier | `"cluster-prod-us-west"` |
| `openchami_id` | string | OpenCHAMI unique entity identifier | `"node-001"` |

### Example OpenCHAMI claims

```json
{
  "cluster_id": "cluster-prod-us-west",
  "openchami_id": "node-001"
}
```

---

## Example full JWT payload

Here's a complete example of a TokenSmith JWT with all claim categories:

```json
{
  "iss": "https://tokensmith.example.com",
  "sub": "user123",
  "aud": ["service-a", "service-b"],
  "exp": 1703088000,
  "nbf": 1703080000,
  "iat": 1703084000,
  "jti": "abc123def456",
  "name": "John Doe",
  "email": "john@example.com",
  "email_verified": true,
  "auth_time": 1703084000,
  "amr": ["pwd", "otp"],
  "acr": "urn:mace:incommon:iap:silver",
  "auth_level": "IAL2",
  "auth_factors": 2,
  "auth_methods": ["password", "totp"],
  "auth_events": ["login", "mfa_complete"],
  "scope": ["read", "write", "admin"],
  "session_id": "sess_abc123xyz789",
  "session_exp": 1703084000,
  "cluster_id": "cluster-prod-us-west",
  "openchami_id": "node-001"
}
```

---

## Decoding and inspecting claims

### Using curl to see JWT claims

```bash
# Get a token and decode it
TOKEN="<your-jwt-token>"

# Decode header
echo "$TOKEN" | cut -d. -f1 | base64 -d | jq .

# Decode claims (payload)
echo "$TOKEN" | cut -d. -f2 | base64 -d | jq .

# Decode signature (not readable without the key)
echo "$TOKEN" | cut -d. -f3 | base64 -d | od -x
```

### Using Go middleware to access claims

```go
import (
    "github.com/OpenCHAMI/tokensmith/pkg/authn"
    "context"
)

func myHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Get verified claims from context
    claims, err := authn.VerifiedClaimsFromContext(ctx)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Use claims
    userID := claims.Subject
    email := claims.Email
    scopes := claims.Scope

    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Hello %s <%s>\n", userID, email)
}
```

---

## Claim validation rules

TokenSmith enforces these validation rules on all tokens:

1. **Expiration (`exp`)**: Token must not be expired at validation time.
2. **Not Before (`nbf`)**: Current time must be >= `nbf`.
3. **Issued At (`iat`)**: Token must not be issued in the future.
4. **Issuer (`iss`)**: Must match the expected issuer.
5. **Subject (`sub`)**: Must not be empty.
6. **Signature**: Must be valid using the correct key.

See [Security Notes](./security-notes.md) for detailed validation policies.

---

## Related documentation

- [Token Flows](./token-flows.md) — Understanding upstream vs local token flows
- [Security Notes](./security-notes.md) — Security considerations for token validation
- [CLI Reference](./cli-reference.md) — Creating tokens with `user-token create`
- [Context Guide](./context-guide.md) — Using TokenSmith middleware with claims
