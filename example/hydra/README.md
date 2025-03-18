# JWT Authentication with Hydra Integration Example

This example demonstrates how to use the JWT authentication middleware with Hydra for external OIDC/SSO integration and service-to-service communication.

## Features

- External token validation through Hydra
- Internal token generation for service-to-service communication
- Scope-based authorization
- Claims extraction from context
- Support for both external and internal tokens
- Automatic token introspection with Hydra

## Prerequisites

- A running Hydra instance (configured with your OIDC provider)
- Go 1.21 or later

## Running the Example

1. Navigate to the example directory:
   ```bash
   cd example/hydra
   ```

2. Update the Hydra admin URL in `main.go` to point to your Hydra instance:
   ```go
   hydraClient := jwtauth.NewHydraClient("http://hydra:4445")
   ```

3. Run the example:
   ```bash
   go run main.go
   ```

4. The server will start on port 8080 and print an example service-to-service token.

## Endpoints

### Public Routes
- `GET /` - Welcome message

### Routes Protected by Hydra (External Tokens)
- `GET /protected` - Protected route requiring valid Hydra token
- `POST /write` - Write scope-protected route

### Routes Protected by Internal Tokens (Service-to-Service)
- `GET /internal` - Protected route requiring valid service token

## Testing the Endpoints

1. External Token Protected Route (requires Hydra token):
   ```bash
   curl -H "Authorization: Bearer YOUR_HYDRA_TOKEN" http://localhost:8080/protected
   ```

2. Internal Token Protected Route (requires service token):
   ```bash
   curl -H "Authorization: Bearer YOUR_SERVICE_TOKEN" http://localhost:8080/internal
   ```

3. Write Scope Protected Route (requires write scope):
   ```bash
   curl -X POST -H "Authorization: Bearer YOUR_HYDRA_TOKEN" http://localhost:8080/write
   ```

## Token Types

### External Tokens (Hydra)
- Validated through Hydra's introspection endpoint
- Claims are extracted from the external token
- Internal tokens are generated based on external token claims

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

## Hydra Integration

The middleware handles Hydra integration by:
1. Receiving external tokens
2. Validating them through Hydra's introspection endpoint
3. Creating internal tokens based on the validated claims
4. Making the claims available in the request context

This allows your services to:
- Accept tokens from external identity providers
- Maintain consistent authorization across your system
- Support service-to-service communication
- Handle token rotation and key management 