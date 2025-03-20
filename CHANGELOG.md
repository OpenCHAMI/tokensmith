# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Support for local token introspection using JWKS
- New configuration file support with `--config` flag
- `generate-config` command to create default configuration files
- Support for multiple OIDC providers (Hydra, Authelia, Keycloak)
- Group-based scope mapping for fine-grained access control
- Service token generation for inter-service communication
- JWT validation and parsing capabilities
- JWKS caching for improved performance
- Docker environment variables for configuration:
  - `TOKENSMITH_ISSUER`
  - `TOKENSMITH_CLUSTER_ID`
  - `TOKENSMITH_OPENCHAMI_ID`
  - `TOKENSMITH_CONFIG`

### Changed
- Updated OIDC provider interface to support local introspection
- Replaced standard `http.ServeMux` with `chi` router for better routing capabilities
- Enhanced token service to handle multiple group scopes
- Improved error handling and validation in token processing
- Updated test suite to cover new functionality

### Fixed
- Token validation and parsing issues
- Group scope mapping edge cases
- JWKS caching and update logic
- Service token generation validation

### Security
- Added support for PKI-based token validation
- Implemented proper token expiration handling
- Enhanced scope validation for service tokens
- Added support for email verification status

### Documentation
- Added comprehensive README with setup and usage instructions
- Added configuration file documentation
- Added API documentation for token service
- Added provider-specific configuration examples

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