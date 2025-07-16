#!/bin/bash

# Generate RSA key for Authelia OIDC
# This script generates a new RSA key pair and creates the Authelia configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/configuration.yml"
KEY_FILE="${SCRIPT_DIR}/config/oidc-key.pem"

echo "Generating RSA key for Authelia OIDC..."

# Generate RSA private key
openssl genrsa -out "$KEY_FILE" 2048

# Create the configuration file with the embedded key
cat > "$CONFIG_FILE" << 'EOF'
---
# Authelia Configuration
# Minimal configuration for TokenSmith integration testing

# Server configuration
server:
  address: 0.0.0.0:9091

# Logging
log:
  level: debug

# Identity validation
identity_validation:
  reset_password:
    jwt_secret: a_very_long_secret_key_for_testing_purposes

# Authentication backend
authentication_backend:
  file:
    path: /config/users_database.yml
    password:
      algorithm: argon2id
      iterations: 1
      salt_length: 16
      parallelism: 8
      memory: 64

# Access control
access_control:
  default_policy: one_factor
  rules:
    - domain: "*.openchami.demo"
      policy: one_factor

# Session configuration
session:
  name: authelia_session
  secret: a_very_long_secret_key_for_testing_purposes
  expiration: 3600
  inactivity: 300
  cookies:
    - name: authelia_session
      domain: openchami.demo
      authelia_url: https://auth.openchami.demo:9091

# Storage
storage:
  local:
    path: /config/db.sqlite3
  encryption_key: a_very_long_secret_key_for_testing_purposes

# Notifier
notifier:
  filesystem:
    filename: /config/notification.txt

# Identity providers (OIDC)
identity_providers:
  oidc:
    jwks:
      - key_id: authelia-oidc-key
        algorithm: RS256
        use: sig
        key: |
EOF

# Add the private key to the config
cat "$KEY_FILE" | sed 's/^/          /' >> "$CONFIG_FILE"

# Add the rest of the config
cat >> "$CONFIG_FILE" << 'EOF'
    clients:
      - client_id: tokensmith
        client_secret: tokensmith_secret_key_for_testing
        redirect_uris:
          - https://tokensmith.openchami.demo:8080/auth/callback
        scopes:
          - openid
          - profile
          - email
        grant_types:
          - authorization_code
        response_types:
          - code
EOF

echo "RSA key generated and configuration updated successfully!"
echo "Key file: $KEY_FILE"
echo "Configuration updated: $CONFIG_FILE"

# Clean up the temporary key file
rm -f "$KEY_FILE" 