# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Admin API and in-memory mapping store (YAML-backed MVP) for mapping upstream claims/groups → internal scopes/roles.
- Scoped-token issuance flow: exchange an upstream OIDC id_token for a short-lived internal scoped token (role or fine-grained scopes).
- JWKS caching and key selection by `kid` with background refresh.
- Non-enforcing validation option for middleware and claim validation.
- Authelia integration for testing and examples.
- Docker Buildx and CI workflows (GoReleaser + GitHub Actions) for multi-arch builds and release automation.
- Integration tests and example integration configuration (TokenSmith ↔ Authelia).
- Utility: GenerateRSAKeyPair (renamed from GenerateKeyPair) for FIPS clarity.

### Changed
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