<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# JWT Authentication Middleware Example

This example demonstrates how to use the JWT authentication middleware with a chi router. It shows both static key and JWKS (JSON Web Key Set) usage.

## Features

- Public and protected routes
- JWT token validation
- Scope-based authorization
- Claims extraction from context
- Support for both static keys and JWKS URLs
- Automatic JWKS refresh
- Example token generation

## Running the Example

1. Navigate to the example directory:
   ```bash
   cd example
   ```

2. Run the example:
   ```bash
   go run main.go
   ```

3. The server will start on port 8080 and print a test token.

## Endpoints

### Public Routes
- `GET /` - Welcome message

### Protected Routes (Static Key)
- `GET /protected-static` - Protected route using static key validation

### Protected Routes (JWKS)
- `GET /protected-jwks` - Protected route using JWKS validation
- `POST /write` - Write scope-protected route

## Testing the Endpoints

1. Static Key Protected Route:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/protected-static
   ```

2. JWKS Protected Route:
   ```bash
   curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/protected-jwks
   ```

3. Write Scope Protected Route:
   ```bash
   curl -X POST -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8080/write
   ```

## Token Claims

The example token includes the following claims:
- `sub`: Subject (user ID)
- `iss`: Issuer
- `aud`: Audience
- `exp`: Expiration time
- `iat`: Issued at time
- `scope`: Array of scopes (read, write)
- `name`: User's name
- `email`: User's email
- `email_verified`: Email verification status

## JWKS Support

The middleware supports both static keys and JWKS URLs. When using a JWKS URL:

1. The middleware will fetch the JWKS from the specified URL
2. It will automatically refresh the JWKS cache based on the configured interval
3. Token validation will use the appropriate key from the JWKS based on the token's `kid` header

To use JWKS, configure the middleware options with:
```go
opts := jwtauth.DefaultMiddlewareOptions()
opts.JWKSURL = "https://your-tenant.auth0.com/.well-known/jwks.json"
opts.JWKSRefreshInterval = 15 * time.Minute
```

The middleware will handle key rotation automatically by refreshing the JWKS cache. 