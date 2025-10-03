#!/bin/sh

# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

# Generate RSA key for Authelia OIDC
# This script generates a new RSA key pair and updates the Authelia configuration

set -e # Exit on error

echo "Generating RSA key for Authelia OIDC..."

CONFIG_FILE="/config/configuration.yml"
KEY_FILE="/config/oidc-key.pem"

# Generate RSA private key
openssl genrsa -out "$KEY_FILE" 2048

# Extract the private key in PEM format
PRIVATE_KEY=$(cat "$KEY_FILE" | sed 's/^/          /')

# Update the configuration file
sed -i "s|PLACEHOLDER_KEY_WILL_BE_REPLACED_BY_SCRIPT|$PRIVATE_KEY|" "$CONFIG_FILE"

echo "RSA key generated and configuration updated successfully!"
echo "Key file: $KEY_FILE"
echo "Configuration updated: $CONFIG_FILE"

# Clean up the temporary key file
rm -f "$KEY_FILE" 