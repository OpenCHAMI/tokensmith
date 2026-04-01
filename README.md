<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith

TokenSmith bridges external OIDC user identity with internal identity and access management using signed JWTs. It provides internal service-to-service identity and access management, along with a standalone chi middleware for JWT verification using PKI.

## Badges

[![REUSE status](https://api.reuse.software/badge/github.com/OpenCHAMI/tokensmith)](https://api.reuse.software/info/github.com/OpenCHAMI/tokensmith)[![golangci-lint](https://github.com/OpenCHAMI/tokensmith/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/OpenCHAMI/tokensmith/actions/workflows/golangci-lint.yaml)
[![Build](https://github.com/OpenCHAMI/tokensmith/actions/workflows/Release.yaml/badge.svg)](https://github.com/OpenCHAMI/tokensmith/actions/workflows/Release.yaml)
[![Release](https://img.shields.io/github/v/release/OpenCHAMI/tokensmith?sort=semver)](https://github.com/OpenCHAMI/tokensmith/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/OpenCHAMI/tokensmith.svg)](https://pkg.go.dev/github.com/OpenCHAMI/tokensmith)
[![Go Report Card](https://goreportcard.com/badge/github.com/OpenCHAMI/tokensmith)](https://goreportcard.com/report/github.com/OpenCHAMI/tokensmith)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/OpenCHAMI/tokensmith/badge)](https://securityscorecards.dev/viewer/?uri=github.com/OpenCHAMI/tokensmith)

## Token Flow

```mermaid
sequenceDiagram
    participant User
    participant OIDC
    participant TokenSmith
    participant ServiceA
    participant ServiceB

    %% User Authentication Flow
    User->>OIDC: Authenticate
    OIDC-->>User: ID Token
    User->>TokenSmith: Exchange ID Token
    TokenSmith-->>User: Internal JWT
    User->>ServiceA: Request with Internal JWT

    %% Service-to-Service Flow
    ServiceA->>TokenSmith: Request Service Token
    TokenSmith-->>ServiceA: Service JWT
    ServiceA->>ServiceB: Request with Service JWT
    ServiceB->>ServiceB: Verify JWT (Middleware)
```

## Start Here

TokenSmith now supports both token exchange and Casbin-first AuthN/AuthZ middleware.

- New adopters: [`docs/getting-started.md`](docs/getting-started.md)
- Internal-only service-to-service setup: [`docs/getting-started.md#15-internal-service-to-service-only-no-external-user-token-exchange`](docs/getting-started.md#15-internal-service-to-service-only-no-external-user-token-exchange)
- Internal-only service-to-service quick guide: [`docs/internal-service-auth.md`](docs/internal-service-auth.md)
- Casbin model and policy workflow: [`docs/casbin-first-guide.md`](docs/casbin-first-guide.md)
- Policy loading and `policy_version`: [`docs/authz_policy.md`](docs/authz_policy.md)
- Operations and rollout modes: [`docs/authz_operations.md`](docs/authz_operations.md)
- Migration from legacy context helpers: [`docs/migration.md`](docs/migration.md)
- Fabrica integration: [`docs/fabrica.md`](docs/fabrica.md)

## Features

- **Identity Bridging**
  - Exchange external OIDC tokens for internal JWTs
  - Map external identities to internal service identities
  - Dynamic authorization and scope management via policy engines
  - Support for multiple OIDC providers (Keycloak, Hydra, Authelia)

- **Service-to-Service Authentication**
  - Secure internal service communication
  - PKI-based JWT signing and verification
  - Service-specific claims and scopes
  - Automatic token validation

- **JWT Middleware**
  - Standalone chi middleware for JWT verification
  - PKI-based signature validation
  - Support for RSA key pairs and JWKS
  - Scope-based authorization
  - Service-to-service authentication
  - Extensible claims handling
  - Casbin integration for policy-based authorization

- **OIDC Provider Support**
  - Keycloak integration
  - Hydra integration
  - Authelia integration
  - Extensible provider interface

## Quick Start

Generate a default config and run the service:

```bash
tokensmith generate-config --config ./config.json
tokensmith serve --config ./config.json --key-dir ./keys --oidc-issuer https://issuer.example
```

For complete startup options and environment variable precedence:

- CLI reference: [`docs/cli-reference.md`](docs/cli-reference.md)
- Environment reference: [`docs/env-reference.md`](docs/env-reference.md)

## Project Structure

```text
tokensmith/
├── cmd/
│   └── tokenservice/         # CLI entrypoint (`tokensmith`)
├── pkg/
│   ├── keys/               # Key management utilities
│   ├── authn/              # JWT validation + principal mapping middleware
│   ├── authz/              # Casbin-first authorization contract + middleware
│   ├── token/              # JWT token management
│   ├── tokenservice/       # Token exchange service
│   └── testutil/           # Public testing helpers for downstream services
├── docs/                   # AuthZ contract and operations docs
├── examples/
│   └── minisvc/            # AuthN/AuthZ integration example
└── tests/
    └── integration/         # End-to-end integration setup
```

## Local Installation

### Main Service

```bash
go get github.com/openchami/tokensmith
```

### JWT Middleware

```bash
go get github.com/openchami/tokensmith/middleware
```

See the [middleware documentation](middleware/README.md) for detailed usage instructions.

For new services, prefer the AuthN/AuthZ middleware stack documented in [`docs/getting-started.md`](docs/getting-started.md).

## Testing (local developer guidance)

Recommended local verification (CI may not run all of these):

```sh
go test ./...
go test -race ./...
go vet ./...
```

## Authorization (Casbin-first)

TokenSmith AuthZ is **Casbin-first**: `model.conf` + `policy.csv` + `grouping.csv` are the external interface.

Start here:

- Casbin-first guide: [`docs/casbin-first-guide.md`](docs/casbin-first-guide.md)

Normative (frozen) wire behavior:

- [`docs/authz-spec.md`](docs/authz-spec.md)

Additional normative contract text:

- [`docs/authz_contract.md`](docs/authz_contract.md)

Operational policy loading details:

- [`docs/authz_policy.md`](docs/authz_policy.md)
- [`docs/authz_operations.md`](docs/authz_operations.md)

Diagnostics endpoint and startup logging guidance:

- [`docs/authz_operations.md#diagnostics-endpoint-recommended`](docs/authz_operations.md#diagnostics-endpoint-recommended)

Security/threat model notes:

- [`docs/security-notes.md`](docs/security-notes.md)

Fabrica integration guidance:

- [`docs/fabrica.md`](docs/fabrica.md)

### Embedded baseline policy

TokenSmith embeds a baseline Casbin model + policy that implements the minimum OpenCHAMI RBAC roles:

- `admin`: full CRUD on all resources across all services
- `operator`: read/write on boot + metadata + SMD state; **no delete**
- `viewer`: read-only access to all resources
- `service`: service-to-service calls (e.g., boot-service reading metadata)

Services can run with only the embedded baseline policy, or extend it with filesystem policy fragments.

### Policy lifecycle

- Policies are loaded at **process startup**.
- **No hot reload** in v1: changing policy fragments requires a **restart**.

### Modes (off → shadow → enforce)

Services SHOULD roll out authorization in stages:

1. **off**: authorization disabled
2. **shadow**: evaluate and emit metrics/logs, but do not block requests
3. **enforce**: block denied requests (HTTP 403 with the TokenSmith error body)

### Observability: policy version hash

TokenSmith computes a deterministic policy hash (`policy_version`) for the effective policy set.

Operators should confirm `policy_version` in:

- service startup logs (policy load)
- AuthZ decision logs/metrics (shadow/enforce)
- the 403 JSON error body returned by the AuthZ middleware in `enforce` mode

This makes it possible to confirm exactly which policy is in effect across a fleet.

### Troubleshooting checklist

- If you changed policy fragments but behavior did not change: you likely need a **restart** (no hot reload).
- Compare `policy_version` across pods to ensure the same policy is mounted everywhere.
- In shadow mode, look for *shadow denials* in AuthZ decision metrics/logs to identify what will break when switching to enforce.

## Test utilities (for downstream integration tests)

TokenSmith exposes a small public `pkg/testutil` package intended for **service integration tests**.

Compatibility policy:

- Best-effort stability within a major version of TokenSmith.
- No guarantees are made about internal structures or unexported behavior.
- Do not use these helpers in production code.

## CLI and Configuration

- CLI commands and flags: [`docs/cli-reference.md`](docs/cli-reference.md)
- Environment variables: [`docs/env-reference.md`](docs/env-reference.md)
- Config schema (`groupScopes`): [`docs/cli-reference.md`](docs/cli-reference.md#configuration-file-schema)

## Development

### Prerequisites

- Go 1.21 or later
- Access to an OIDC provider (Keycloak, Hydra, or Authelia)

### Build & Install

This project uses [GoReleaser](https://goreleaser.com/) to automate releases and embed additional build metadata (commit info, build time, versioning, etc.).

#### 1. Environment Variables

Before building, make sure to set the following environment variables to include detailed build metadata:

- **GIT_STATE**: Indicates whether there are uncommitted changes. (`clean` if no changes, `dirty` if there are.)
- **BUILD_HOST**: Hostname of the machine performing the build.
- **GO_VERSION**: The version of Go used.
- **BUILD_USER**: The username of the person or system performing the build.

Example:

```bash
export GIT_STATE=$(if git diff-index --quiet HEAD --; then echo 'clean'; else echo 'dirty'; fi)
export BUILD_HOST=$(hostname)
export GO_VERSION=$(go version | awk '{print $3}')
export BUILD_USER=$(whoami)
```

#### 2. Installing GoReleaser

Follow the official [GoReleaser installation instructions](https://goreleaser.com/install/) to set up GoReleaser locally.

#### 3. Building Locally with GoReleaser

Use snapshot mode to build locally without releasing:

```bash
goreleaser release --snapshot --clean
```

- The build artifacts (including embedded metadata) will be placed in the `dist/` directory.
- Inspect the resulting binaries to ensure the metadata was correctly embedded.

### Testing

```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./pkg/tokenservice
go test ./pkg/authn
go test ./pkg/authz
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See the [OpenCHAMI Contributors Guide](https://github.com/OpenCHAMI/.github/blob/main/CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- OpenCHAMI community
- OIDC provider maintainers
- Contributors and maintainers of this project
