<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# JWT Middleware for Go

A flexible and feature-rich JWT middleware for Go applications that supports token validation, scope checking, and service-to-service authentication.

## Features

- JWT token validation with support for:
  - RSA key pairs
  - JSON Web Key Sets (JWKS)
  - Automatic JWKS refresh
- Configurable validation options:
  - Token expiration
  - Issuer validation
  - Audience validation
  - Required claims
- Scope-based authorization
- Service-to-service token validation
- Extensible claims handling
- Context-based claims access

## Installation

```bash
go get github.com/openchami/tokensmith/middleware
```

## Quick Start

```go
package main

import (
    "net/http"
    "github.com/openchami/tokensmith/middleware"
)

func main() {
    // Create middleware options
    opts := middleware.DefaultMiddlewareOptions()
    opts.JWKSURL = "https://your-auth-server/.well-known/jwks.json"

    // Create the JWT middleware
    jwtMiddleware := middleware.JWTMiddleware(nil, opts)

    // Create your handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get claims from context
        claims, err := middleware.GetClaimsFromContext(r.Context())
        if err != nil {
            http.Error(w, "Failed to get claims", http.StatusInternalServerError)
            return
        }

        // Use claims
        w.Write([]byte("Hello, " + claims.Subject))
    })

    // Apply middleware
    http.Handle("/protected", jwtMiddleware(handler))
    http.ListenAndServe(":8080", nil)
}
```

## Configuration

### MiddlewareOptions

```go
type MiddlewareOptions struct {
    AllowEmptyToken     bool          // Allow requests without a token
    ValidateExpiration  bool          // Enable expiration validation
    ValidateIssuer      bool          // Enable issuer validation
    ValidateAudience    bool          // Enable audience validation
    RequiredClaims      []string      // List of required claims
    JWKSURL            string        // URL to fetch JWKS from
    JWKSRefreshInterval time.Duration // How often to refresh JWKS
}
```

### Default Options

```go
opts := middleware.DefaultMiddlewareOptions()
```

## Usage Examples

### Basic Token Validation

```go
opts := middleware.DefaultMiddlewareOptions()
jwtMiddleware := middleware.JWTMiddleware(publicKey, opts)
handler := jwtMiddleware(yourHandler)
```

### Using JWKS

```go
opts := &middleware.MiddlewareOptions{
    JWKSURL:            "https://your-auth-server/.well-known/jwks.json",
    JWKSRefreshInterval: time.Hour,
}
jwtMiddleware := middleware.JWTMiddleware(nil, opts)
```

### Scope-Based Authorization

```go
// Require a single scope
scopeMiddleware := middleware.RequireScope("read")
handler := scopeMiddleware(yourHandler)

// Require multiple scopes
scopesMiddleware := middleware.RequireScopes([]string{"read", "write"})
handler := scopesMiddleware(yourHandler)
```

### Service-to-Service Authentication

```go
// Require service token with specific target service
serviceMiddleware := middleware.RequireServiceToken("target-service")
handler := serviceMiddleware(yourHandler)
```

### Accessing Claims

```go
func handler(w http.ResponseWriter, r *http.Request) {
    // Get standard claims
    claims, err := middleware.GetClaimsFromContext(r.Context())
    if err != nil {
        http.Error(w, "Failed to get claims", http.StatusInternalServerError)
        return
    }

    // Access claim fields
    subject := claims.Subject
    scopes := claims.Scope
    email := claims.Email

    // Get raw claims for custom fields
    rawClaims, err := middleware.GetRawClaimsFromContext(r.Context())
    if err != nil {
        http.Error(w, "Failed to get raw claims", http.StatusInternalServerError)
        return
    }

    // Access custom claims
    customField := rawClaims["custom_field"]
}
```

## Claims Structure

The middleware supports the following standard claims:

```go
type Claims struct {
    Issuer         string   `json:"iss,omitempty"`
    Subject        string   `json:"sub,omitempty"`
    Audience       []string `json:"aud,omitempty"`
    ExpirationTime int64    `json:"exp,omitempty"`
    NotBefore      int64    `json:"nbf,omitempty"`
    IssuedAt       int64    `json:"iat,omitempty"`
    Scope          []string `json:"scope,omitempty"`
    Name           string   `json:"name,omitempty"`
    Email          string   `json:"email,omitempty"`
    EmailVerified  bool     `json:"email_verified,omitempty"`
    ClusterID      string   `json:"cluster_id,omitempty"`
    OpenCHAMIID    string   `json:"openchami_id,omitempty"`
    Groups         []string `json:"groups,omitempty"`
}
```

## Error Handling

The middleware returns appropriate HTTP status codes:

- `401 Unauthorized`: Invalid or missing token
- `403 Forbidden`: Insufficient scopes or invalid service token
- `500 Internal Server Error`: Server-side errors (e.g., JWKS fetch failures)

## Best Practices

1. Always use HTTPS in production
2. Configure appropriate token expiration times
3. Use JWKS for dynamic key rotation
4. Implement proper error handling
5. Validate all required claims
6. Use scope-based authorization for fine-grained access control

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
