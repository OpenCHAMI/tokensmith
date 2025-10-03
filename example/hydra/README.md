<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# JWT Authentication with OIDC Integration Example

This example demonstrates how to use the JWT authentication middleware with any OIDC-compliant provider (including Hydra) for external OIDC/SSO integration and service-to-service communication.

## Features

- External token validation through any OIDC-compliant provider
- Internal token generation for service-to-service communication
- Scope-based authorization
- Claims extraction from context
- Support for both external and internal tokens
- Automatic token introspection with OIDC discovery

## Prerequisites

- A running OIDC-compliant provider (Hydra, Keycloak, Authelia, etc.)
- Go 1.21 or later

## Running the Example

1. Navigate to the example directory:
   ```bash
   cd example/hydra
   ```

2. Update the OIDC provider URL in `main.go` to point to your OIDC provider:
   ```go
   oidcProvider := oidc.NewSimpleProvider("http://hydra:4444", "test-client-id", "test-client-secret")
   ```

3. Run the example:
   ```bash
   go run main.go
   ```

4. The server will start on port 8080 and print an example service-to-service token.

## Endpoints

### Public Routes
- `GET /` - Welcome message

### Routes Protected by OIDC Provider (External Tokens)
- `GET /protected` - Protected route requiring valid OIDC token
- `POST /write` - Write scope-protected route

### Routes Protected by Internal Tokens (Service-to-Service)
- `GET /internal` - Protected route requiring valid service token

## Testing the Endpoints

1. External Token Protected Route (requires OIDC token):
   ```bash
   curl -H "Authorization: Bearer YOUR_OIDC_TOKEN" http://localhost:8080/protected
   ```

2. Internal Token Protected Route (requires service token):
   ```bash
   curl -H "Authorization: Bearer YOUR_SERVICE_TOKEN" http://localhost:8080/internal
   ```

3. Write Scope Protected Route (requires write scope in OIDC token):
   ```bash
   curl -X POST -H "Authorization: Bearer YOUR_OIDC_TOKEN" http://localhost:8080/write
   ```

## Token Types

### External Tokens (OIDC Provider)
- Validated through OIDC discovery and introspection endpoint
- Claims are extracted from the external token
- Works with any OIDC-compliant provider (Hydra, Keycloak, Authelia, etc.)

### Internal Tokens (Service-to-Service)
- Generated using the internal key pair
- Used for service-to-service communication
- Include service-specific claims and scopes

## Service-to-Service Communication

To create a service-to-service token:

```go
token, err := tokenManager.CreateServiceToken(jwtauth.ServiceTokenOptions{
    ServiceName:    "service-a",
    TargetService:  "service-b",
    Expiration:     1 * time.Hour,
    Scopes:        []string{"read", "write"},
})
```

The generated token will include:
- Subject: `service:service-a`
- Audience: `service:service-b`
- Scopes: `read`, `write`
- Standard JWT claims (iss, exp, iat, etc.)

## OIDC Integration

The middleware handles OIDC integration by:
1. Receiving external tokens
2. Using OIDC discovery to find provider endpoints
3. Validating tokens through the provider's introspection endpoint
4. Making the claims available in the request context

This allows your services to:
- Accept tokens from any OIDC-compliant identity provider
- Maintain consistent authorization across your system
- Support service-to-service communication
- Handle token rotation and key management automatically
