# Policy Engine Package

The `policy` package provides pluggable policy engines for determining token scopes, audiences, and permissions in the OpenCHAMI TokenSmith service. This package allows for flexible policy decisions based on user identity, groups, and other contextual information.

## Overview

Policy engines are responsible for determining what scopes, audiences, and permissions should be granted to a user when they exchange an identity token from an upstream OIDC provider for an access token. The package provides a common interface and two reference implementations:

1. **Static Policy Engine** - Always returns the same hardcoded scopes, audiences, and permissions
2. **File-Based Policy Engine** - Reads policy configuration from a file with role-based access control

## Core Concepts

### PolicyDecision

A `PolicyDecision` represents the result of a policy evaluation and contains:

- **Scopes**: OAuth 2.0 scopes granted to the user
- **Audiences**: Intended recipients of the token
- **Permissions**: Specific permissions granted to the user
- **TokenLifetime**: Duration for which the token should be valid (optional)
- **AdditionalClaims**: Custom claims to be included in the token (optional)

### PolicyContext

A `PolicyContext` contains the information needed for policy evaluation:

- **Username**: User identifier from the upstream OIDC provider
- **Groups**: User's group memberships
- **Claims**: Additional claims from the upstream token
- **RequestContext**: Request metadata (IP, user agent, etc.)
- **ClusterID**: OpenCHAMI cluster identifier
- **OpenCHAMIID**: OpenCHAMI entity identifier

### Engine Interface

All policy engines implement the `Engine` interface:

```go
type Engine interface {
    EvaluatePolicy(ctx context.Context, policyCtx *PolicyContext) (*PolicyDecision, error)
    GetName() string
    GetVersion() string
    ValidateConfiguration() error
}
```

## Static Policy Engine

The static policy engine always returns the same hardcoded policy decision regardless of user context. This is useful for simple deployments where all users should receive the same permissions.

### Configuration

```go
config := &policy.StaticEngineConfig{
    Name:        "my-static-engine",
    Version:     "1.0.0",
    Scopes:      []string{"read", "write"},
    Audiences:   []string{"smd", "bss", "cloud-init"},
    Permissions: []string{"read:basic", "write:basic"},
    TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
    AdditionalClaims: map[string]interface{}{
        "policy_engine": "static",
        "environment":   "production",
    },
}

engine, err := policy.NewStaticEngine(config)
```

### Example Usage

```go
ctx := context.Background()
policyCtx := &policy.PolicyContext{
    Username: "user123",
    Groups:   []string{"admin", "user"},
    Claims:   map[string]interface{}{"email": "user@example.com"},
}

decision, err := engine.EvaluatePolicy(ctx, policyCtx)
if err != nil {
    log.Fatal(err)
}

// decision.Scopes = ["read", "write"]
// decision.Audiences = ["smd", "bss", "cloud-init"]
// decision.Permissions = ["read:basic", "write:basic"]
```

## File-Based Policy Engine

The file-based policy engine reads policy configuration from a JSON file and supports role-based access control. Users can be mapped to multiple roles, and each role has associated scopes, audiences, and permissions.

### Configuration File Format

```json
{
  "version": "1.0.0",
  "default_policy": {
    "scopes": ["read"],
    "audiences": ["default-service"],
    "permissions": ["read:basic"]
  },
  "roles": {
    "admin": {
      "name": "Administrator",
      "description": "Full administrative access",
      "scopes": ["read", "write", "admin"],
      "audiences": ["admin-service", "smd", "bss"],
      "permissions": ["read:all", "write:all", "admin:all"],
      "token_lifetime": "2h",
      "additional_claims": {
        "role": "admin",
        "level": "high"
      }
    },
    "user": {
      "name": "Regular User",
      "description": "Basic user access",
      "scopes": ["read"],
      "audiences": ["user-service"],
      "permissions": ["read:basic"],
      "token_lifetime": "1h"
    },
    "operator": {
      "name": "System Operator",
      "description": "System operation and monitoring",
      "scopes": ["read", "write", "monitor"],
      "audiences": ["operator-service", "monitoring"],
      "permissions": ["read:system", "write:system", "monitor:all"]
    }
  },
  "user_role_mappings": {
    "adminuser": ["admin"],
    "regularuser": ["user"],
    "operatoruser": ["operator"],
    "poweruser": ["user", "operator"]
  },
  "group_role_mappings": {
    "admins": ["admin"],
    "users": ["user"],
    "operators": ["operator"],
    "power-users": ["user", "operator"]
  }
}
```

### Configuration

```go
config := &policy.FileBasedEngineConfig{
    Name:       "my-file-engine",
    Version:    "1.0.0",
    ConfigPath: "/etc/tokensmith/policy.json",
    ReloadInterval: func() *time.Duration { d := 5 * time.Minute; return &d }(),
}

engine, err := policy.NewFileBasedEngine(config)
```

### Example Usage

```go
ctx := context.Background()
policyCtx := &policy.PolicyContext{
    Username: "adminuser",
    Groups:   []string{"admins"},
    Claims:   map[string]interface{}{"email": "admin@example.com"},
}

decision, err := engine.EvaluatePolicy(ctx, policyCtx)
if err != nil {
    log.Fatal(err)
}

// For adminuser with admin role:
// decision.Scopes = ["read", "write", "admin"]
// decision.Audiences = ["admin-service", "smd", "bss"]
// decision.Permissions = ["read:all", "write:all", "admin:all"]
```

## Policy Decision Merging

When a user has multiple roles, their policy decisions are automatically merged:

- **Scopes**: Combined and deduplicated
- **Audiences**: Combined and deduplicated
- **Permissions**: Combined and deduplicated
- **TokenLifetime**: Uses the first non-nil value
- **AdditionalClaims**: Merged with later decisions taking precedence

## Creating Custom Policy Engines

To create a custom policy engine, implement the `Engine` interface:

```go
type MyCustomEngine struct {
    // Your engine-specific fields
}

func (e *MyCustomEngine) EvaluatePolicy(ctx context.Context, policyCtx *PolicyContext) (*PolicyDecision, error) {
    // Your policy evaluation logic
    return &PolicyDecision{
        Scopes:      []string{"custom-scope"},
        Audiences:   []string{"custom-service"},
        Permissions: []string{"custom:permission"},
    }, nil
}

func (e *MyCustomEngine) GetName() string {
    return "my-custom-engine"
}

func (e *MyCustomEngine) GetVersion() string {
    return "1.0.0"
}

func (e *MyCustomEngine) ValidateConfiguration() error {
    // Your configuration validation logic
    return nil
}
```

## Thread Safety

All policy engines must be thread-safe as they may be called concurrently from multiple goroutines. The provided implementations use appropriate synchronization mechanisms to ensure thread safety.

## Error Handling

Policy engines should handle errors gracefully and provide meaningful error messages. Common error scenarios include:

- Invalid configuration
- Missing or malformed policy files
- Network timeouts (for remote policy services)
- Invalid user context

## Performance Considerations

- Policy evaluation should be fast as it's called for every token exchange
- Consider caching policy decisions for frequently accessed users
- Use appropriate data structures for efficient lookups
- Avoid blocking operations in policy evaluation

## Security Considerations

- Validate all input data thoroughly
- Sanitize user-provided data before use
- Use secure file permissions for policy configuration files
- Consider using signed policy files for integrity verification
- Implement proper access controls for policy configuration management
