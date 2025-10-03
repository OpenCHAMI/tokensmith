<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Pluggable Policy Engine System**: Introduced a flexible policy engine architecture for determining scopes, audiences, and permissions in access tokens.
  - **Static Policy Engine**: Simple hardcoded policy engine with configurable scopes, audiences, and permissions.
  - **File-Based Policy Engine**: Dynamic policy engine that reads configuration from JSON files with role-based access control (RBAC).
  - **Policy Engine Interface**: Extensible interface allowing custom policy implementations.
  - **Role-Based Access Control**: Support for user and group role mappings with fine-grained permissions.
  - **Policy Configuration Management**: JSON-based policy configuration with hot reloading support.
- **Command-Line Policy Engine Integration**: Added CLI flags and commands for policy engine configuration.
  - `--policy-engine` flag to select policy engine type (static, file-based).
  - `--policy-config` flag to specify policy configuration file path.
  - `generate-policy-config` command to create default policy configuration files.
- **Enhanced Token Exchange**: Policy engines now determine scopes, audiences, and permissions dynamically during token exchange.
- Admin API and in-memory mapping store (YAML-backed MVP) for mapping upstream claims/groups → internal scopes/roles.
- Scoped-token issuance flow: exchange an upstream OIDC id_token for a short-lived internal scoped token (role or fine-grained scopes).
- JWKS caching and key selection by `kid` with background refresh.
- Non-enforcing validation option for middleware and claim validation.
- Authelia integration for testing and examples.
- Docker Buildx and CI workflows (GoReleaser + GitHub Actions) for multi-arch builds and release automation.
- Integration tests and example integration configuration (TokenSmith ↔ Authelia).
- Utility: GenerateRSAKeyPair (renamed from GenerateKeyPair) for FIPS clarity.

### Changed
- **Token Exchange Architecture**: Replaced hardcoded group-to-scope mapping with pluggable policy engine system.
- **TokenService Configuration**: Enhanced configuration structure to support policy engine selection and configuration.
- **Command-Line Interface**: Updated CLI to support policy engine configuration with new flags and commands.
- Refactored jwt-related code into clearer packages and updated claims structure to embed `jwt.RegisteredClaims`.
- Replaced lestrrat-go/jwx middleware with `github.com/golang-jwt/jwt/v5` for parsing/validation.
- Token generation and service token flows updated to use `jwt.NewNumericDate` and proper RegisteredClaims usage.
- TokenManager.ParseToken now parses into custom `TSClaims` and invokes `TSClaims.Validate()` for centralized validation.
- Improved key management and NIST/FIPS-oriented naming and algorithms.
- Updated dependencies; tidied `go.mod` and resolved module import casing issues (canonicalized to `github.com/openchami/tokensmith`).
- Refactored middleware and tokenservice structure for clearer responsibilities.

### Fixed
- Linter and build errors caused by incorrect construction of embedded RegisteredClaims fields.
- go mod tidy / import casing issues (added guidance and temporary replace workaround).
- Token parsing/validation bugs related to date/time handling and claim types.
- Group-to-scope mapping edge cases and scope derivation logic.
- Various test fixes to construct `TSClaims` correctly and to validate NIST-required fields.

### Security
- Enforced FIPS-compliant algorithm validation at verification points.
- Short TTLs and session-expiration limits for scoped/service tokens.
- Added PKI-based validation support and improved token expiration handling.
- Enhanced scope validation and added email verification handling where applicable.

### Documentation
- **Policy Engine Documentation**: Added comprehensive documentation for the new policy engine system.
  - Policy engine interface documentation with usage examples.
  - Static policy engine configuration and examples.
  - File-based policy engine configuration with RBAC examples.
  - Policy configuration file format documentation.
- Added feature spec and implementation notes for scoped-token issuance and mapping model.
- Added README updates, configuration docs and example `mappings.yaml`.
- Documented middleware and JWT changes and provided usage examples.

## [0.1.0] - 2025-03-21

### Added
- Initial release
- Basic token service implementation
- OIDC provider integration
- Token exchange functionality
- Service token generation
- JWT validation and parsing
- Configuration management
- HTTP server implementation