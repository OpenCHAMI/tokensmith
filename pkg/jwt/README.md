# JWT Library

A Go library for JWT token generation and verification with chi middleware support.

## Features

- JWT token generation and parsing
- RSA key pair management
- Chi middleware for JWT verification
- Scope-based authorization middleware
- Configurable validation options
- Context-based claims access

## Installation

```bash
go get github.com/yourusername/jwt
```

## Usage

### Basic Token Generation

```go
import "github.com/yourusername/jwt"

// Create a key manager
keyManager, err := jwt.NewKeyManager()
if err != nil {
    log.Fatal(err)
}

// Create a token manager
tokenManager := jwt.NewTokenManager(keyManager)

// Create claims
claims := jwt.NewClaims(
    "issuer",
    "subject",
    []string{"audience"},
)

// Set expiration
claims.SetExpiration(time.Now().Add(24 * time.Hour))

// Generate token
token, err := tokenManager.GenerateToken(claims)
if err != nil {
    log.Fatal(err)
}
```

### Chi Middleware

```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/yourusername/jwt"
)

// Create middleware options
opts := jwt.DefaultMiddlewareOptions()
opts.AllowEmptyToken = true // Optional: allow requests without tokens

// Create middleware
middleware := jwt.Middleware(tokenManager, opts)

// Use in chi router
r := chi.NewRouter()
r.Use(middleware)

// Protected route
r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
    claims, err := jwt.GetClaimsFromContext(r.Context())
    if err != nil {
        http.Error(w, "invalid token", http.StatusUnauthorized)
        return
    }
    // Use claims...
})

// Scope-based protection
r.Group(func(r chi.Router) {
    r.Use(jwt.RequireScope("admin"))
    r.Get("/admin", adminHandler)
})

// Multiple scope requirements
r.Group(func(r chi.Router) {
    r.Use(jwt.RequireScopes([]string{"read", "write"}))
    r.Get("/data", dataHandler)
})
```

## Configuration

### Middleware Options

The middleware can be configured with the following options:

- `AllowEmptyToken`: Allow requests without a token (default: false)
- `ValidateExpiration`: Enable expiration validation (default: true)
- `ValidateIssuer`: Enable issuer validation (default: true)
- `ValidateAudience`: Enable audience validation (default: true)

### Claims

The library supports standard JWT claims and custom claims:

- `Issuer`: Token issuer
- `Subject`: Token subject
- `Audience`: Token audience(s)
- `Expiration`: Token expiration time
- `NotBefore`: Token not-before time
- `IssuedAt`: Token issued-at time
- `Scope`: Token scopes
- `Name`: Subject's name
- `Email`: Subject's email
- `EmailVerified`: Email verification status

## License

MIT License 