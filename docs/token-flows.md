<!--
Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith token flows

This guide describes the primary token flows supported by TokenSmith and when to use each one.

## Overview

TokenSmith supports two main token acquisition paths:

1. **Upstream OIDC flow** (primary): Delegate authentication to an external OIDC provider (e.g., Keycloak, Azure AD, Dex).
2. **Local user token flow** (break-glass): Generate tokens directly for local users when upstream OIDC is unavailable or for administrative access.

## Upstream OIDC flow (recommended)

This is the standard and recommended flow for production deployments.

### How it works

1. **Client** initiates login or requests a resource.
2. **Client** is redirected to the **upstream OIDC provider** (issuer).
3. **OIDC provider** authenticates the user.
4. **Client** receives an authorization code from the **upstream OIDC provider**.
5. **Client** exchanges the authorization code with **TokenSmith** using the RFC 8693 token exchange endpoint.
6. **TokenSmith** validates the code with the **upstream OIDC provider** and returns a **TokenSmith JWT**.
7. **Client** uses the **TokenSmith JWT** to access services.

### Requirements

- Upstream OIDC provider must be reachable from TokenSmith.
- TokenSmith must be configured with the **OIDC issuer URL**, **client ID**, and **client secret**.
- The OIDC provider must support standard discovery (`.well-known/openid-configuration`).

### Configuration

```bash
# Environment variables
export OIDC_ISSUER_URL="https://keycloak.example.com/realms/master"
export OIDC_CLIENT_ID="tokensmith"
export OIDC_CLIENT_SECRET="<secret>"

# Start TokenSmith
tokensmith serve
```

### Runtime reconfiguration

You can reconfigure the upstream OIDC provider without restarting TokenSmith using the CLI:

```bash
tokensmith oidc configure \
  --issuer-url "https://new-provider.example.com" \
  --client-id "new-client-id" \
  --replace-existing
```

This is useful for:
- Migrating to a new OIDC provider
- Failover scenarios (switch to a backup provider)
- Testing a new provider configuration before full rollout

See [CLI reference](./cli-reference.md) for the complete `oidc configure` command.

## Local user token flow (break-glass)

This flow is designed for emergency access when upstream OIDC is unavailable. It should not be used as the primary authentication method.

### How it works

1. **Operator** runs the `tokensmith user-token create` command with a username and scopes.
2. **TokenSmith** generates a JWT directly (no upstream provider required).
3. **Operator** provides the JWT to a user or service.
4. **Client** uses the **TokenSmith JWT** to access services.

### Requirements

- TokenSmith must be started with `--enable-local-user-mint`.
- Operator must have **local access** to the TokenSmith instance (or access via local HTTP endpoint).

### When to use

- **Upstream OIDC is down**: Temporary break-glass access while OIDC provider is recovering.
- **Initial bootstrapping**: Set up admin accounts before OIDC is available.
- **Testing**: Mint test tokens without involving a full OIDC provider.

### Use case: Emergency access

```bash
# Start TokenSmith with local user minting enabled
tokensmith serve --enable-local-user-mint

# In a separate terminal, mint an admin token
tokensmith user-token create \
  --subject "admin-breakglass" \
  --scopes "admin,audit" \
  --enable-local-user-mint
```

### Use case: Initial bootstrap

```bash
# Day 1: Start with local user minting
tokensmith serve --enable-local-user-mint

# Create initial admin account
tokensmith user-token create \
  --subject "admin@example.com" \
  --scopes "admin" \
  --enable-local-user-mint

# Configure the OIDC provider
tokensmith oidc configure \
  --issuer-url "https://keycloak.example.com" \
  --client-id "tokensmith" \
  --replace-existing

# Now stop TokenSmith and restart without --enable-local-user-mint
# (Optional) Disable local user minting in production:
tokensmith serve  # no flag = local user minting disabled
```

## Comparison

| Aspect | Upstream OIDC | Local User Token |
|--------|---------------|------------------|
| **Primary use** | Standard authentication | Emergency access / bootstrap |
| **Provider dependency** | Yes (required) | No |
| **User identity** | From upstream provider | Locally managed |
| **Security context** | Shared with OIDC ecosystem | Isolated to TokenSmith |
| **Auditability** | Yes (upstream + TokenSmith logs) | Requires local audit logs |
| **Scalability** | Suitable for production | Not for production scale |
| **Start flag** | (None) | `--enable-local-user-mint` |

## Decision tree: Which flow should I use?

1. **Do you have an external OIDC provider (Keycloak, Azure AD, Okta, etc.)?**
   - **Yes** → Use [upstream OIDC flow](#upstream-oidc-flow-recommended)
   - **No** → Go to step 2

2. **Do you need to bootstrap a new TokenSmith instance or handle a temporary outage?**
   - **Yes** → Use [local user token flow](#local-user-token-flow-break-glass) with `--enable-local-user-mint`
   - **No** → Wait for OIDC provider to be available

3. **Is the OIDC provider currently unavailable?**
   - **Yes** → Temporarily use [local user token flow](#local-user-token-flow-break-glass)
   - **No** → Return to [upstream OIDC flow](#upstream-oidc-flow-recommended)

## Common scenarios

### Day 1: Bootstrap a new environment

1. Start TokenSmith with local user minting: `tokensmith serve --enable-local-user-mint`
2. Mint initial admin token: `tokensmith user-token create ...`
3. Configure OIDC provider: `tokensmith oidc configure ...`
4. Restart TokenSmith without `--enable-local-user-mint` (or rely on env startup config)

### Day N: Emergency access

1. Verify upstream OIDC is down.
2. Start a temporary TokenSmith instance with `--enable-local-user-mint` (or use an existing instance if it was started with the flag).
3. Mint break-glass tokens for critical operations.
4. After OIDC recovery, retire the break-glass tokens.

### Migration: Switch OIDC providers

1. Configure the new provider: `tokensmith oidc configure --issuer-url <new> --client-id <new> --replace-existing`
2. No restart required; TokenSmith immediately uses the new provider.
3. No downtime; existing connections are not interrupted.

## Related documentation

- [CLI Reference](./cli-reference.md) — `oidc configure`, `oidc status`, `user-token create` commands
- [HTTP Endpoints](./http-endpoints.md) — Local admin endpoints for OIDC configuration
- [Environment Reference](./env-reference.md) — OIDC environment variables and startup behavior
- [Getting Started](./getting-started.md) — Step-by-step setup guide
- [Security Notes](./security-notes.md) — Security considerations for local user minting and admin endpoints
