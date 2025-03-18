# Tokensmith

Tokensmith is a secure JWT token management service and library for OpenCHAMI, providing token generation, validation, and service-to-service authentication capabilities.

## Features

- **JWT Token Management**: Generate and validate JWT tokens with RSA-256 signatures
- **Service-to-Service Authentication**: Secure communication between microservices
- **Hydra Integration**: Seamless integration with Ory Hydra for OAuth2/OpenID Connect
- **Group-based Scope Management**: Automatically assign scopes based on user groups
- **Key Management**: Secure RSA key pair generation and storage
- **Middleware Support**: Easy-to-use middleware for token validation

## Components

### Core Library (`pkg/jwt`)

The core JWT library provides:

- `TokenManager`: Handles JWT token operations (generation, parsing, validation)
- `KeyManager`: Manages RSA key pairs and JWK conversion
- `Claims`: Structured JWT claims with validation
- `Middleware`: HTTP middleware for token validation

### Token Service (`pkg/tokenservice`)

A service layer that provides:

- Token exchange with Hydra integration
- Service token generation
- Group-based scope management
- JWKS endpoint for public key distribution

### Command Line Interface (`cmd/tokenservice`)

A standalone service that exposes the token service functionality via HTTP endpoints:

```bash
tokenservice serve \
  --hydra-url=http://hydra:4445 \
  --issuer=http://tokensmith:8080 \
  --audience=api \
  --port=8080 \
  --key-dir=/etc/tokensmith/keys \
  --cluster-id=test-cluster-id \
  --openchami-id=test-openchami-id
```

## Installation

```bash
go get github.com/openchami/tokensmith
```

## Usage

### Middleware Usage

Tokensmith provides several middleware components for securing your HTTP endpoints:

```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/openchami/tokensmith/pkg/jwt"
)

func main() {
    r := chi.NewRouter()

    // Create managers
    km := jwt.NewKeyManager()
    err := km.LoadPrivateKey("path/to/private.pem")
    if err != nil {
        log.Fatal(err)
    }
    tm := jwt.NewTokenManager(km, "your-issuer")

    // Protect routes with token validation
    r.Group(func(r chi.Router) {
        // Validate JWT tokens
        r.Use(jwt.Middleware(tm))
        
        // Optional: Require specific scopes
        r.With(jwt.RequireScope("admin")).Get("/admin", adminHandler)
        r.With(jwt.RequireScope("read")).Get("/items", listItems)
        
        // Optional: Service-to-service authentication
        r.With(jwt.RequireServiceToken("inventory-service")).Post("/inventory", updateInventory)
    })
}
```

### Complete Example

See the [example](example/) directory for a complete working example, which includes:

1. Token Service Setup (`example/server/main.go`):
```go

...

    // Create key manager
    km := jwt.NewKeyManager()
    if err := km.GenerateKeyPair(2048); err != nil {
        log.Fatalf("Failed to generate key pair: %v", err)
    }

    // Configure token service
    config := tokenservice.Config{
        HydraAdminURL: "http://hydra:4445",
        Issuer:        "https://openchami.example.com",
        Audience:      "openchami-api",
        GroupScopes: map[string][]string{
            "admin":    {"admin", "write", "read"},
            "operator": {"write", "read"},
            "viewer":   {"read"},
            "user":     {"read"},
        },
        ClusterID:   "test-cluster-id",
		OpenCHAMIID: "test-openchami-id",
    }

    // Create token service
    ts := tokenservice.NewTokenService(km, config,)

    // Set up routes
    r := chi.NewRouter()
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)

...

    // Protected API endpoints
    r.Group(func(r chi.Router) {
        // Create token manager for validation
        tm := jwt.NewTokenManager(km, config.Issuer)
        r.Use(jwt.Middleware(tm))
        
        // Admin-only endpoints
        r.Group(func(r chi.Router) {
            r.Use(jwt.RequireScope("admin"))
            r.Post("/users", createUser)
            r.Delete("/users/{id}", deleteUser)
        })

...
```

2. Running the Example:
```bash
# Start Hydra (see example/hydra/README.md for setup)
cd example/hydra
docker-compose up -d

# Start the token service
cd example/server
go run main.go
```

3. Testing the Service:
```bash
# Get a token from Hydra
TOKEN=$(curl -X POST http://localhost:4444/oauth2/token \
    -u "client:secret" \
    -d "grant_type=client_credentials")

# Exchange for a service token
curl -X POST http://localhost:8080/token/service \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"service_id": "inventory", "target_service": "api"}'
```

### As a Service

1. Start the token service:
```bash
tokenservice serve \
  --hydra-url=http://hydra:4445 \
  --issuer=http://tokensmith:8080 \
  --audience=api \
  --port=8080 \
  --key-dir=/etc/tokensmith/keys
```

2. Exchange a Hydra token for an OpenCHAMI token:
```bash
curl -X POST http://localhost:8080/token \
  -H "Authorization: Bearer <hydra-token>" \
  -H "Content-Type: application/json"
```

3. Generate a service token:
```bash
curl -X POST http://localhost:8080/token/service \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"service_id": "service1", "target_service": "service2"}'
```

## Security Features

- RSA-256 signatures for all tokens
- Automatic key rotation support
- Secure key storage
- Token validation:
  - Signature verification
  - Expiration and validity period checks
  - Issuer and audience validation
  - Scope validation
  - Service-specific claims validation

## Configuration

The token service supports the following configuration options:

| Flag | Environment Variable | Description | Default |
|------|---------------------|-------------|---------|
| `--hydra-url` | `HYDRA_ADMIN_URL` | Hydra Admin API URL | `http://hydra:4445` |
| `--issuer` | `ISSUER` | Token issuer identifier | `http://tokensmith:8080` |
| `--audience` | `AUDIENCE` | Default token audience | `api` |
| `--port` | `PORT` | HTTP server port | `8080` |
| `--key-dir` | `KEY_DIR` | Directory for key storage | `/etc/tokensmith/keys` |
| `--cluster-id` | `CLUSTER_ID` | Unique identifier for this cluster | `cl-F00F00F00` |
| `--openchami-id` | `OPENCHAMI_ID` | Unique identifier for this instance of OpenCHAMI | `oc-F00F00F00` |

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 