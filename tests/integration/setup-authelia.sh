#!/bin/bash

# Setup script for Authelia integration testing
# This script generates RSA keys and creates the Authelia configuration

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTHELIA_DIR="${SCRIPT_DIR}/authelia"

echo "Setting up Authelia configuration..."

# Run the key generation script
if [ -f "${AUTHELIA_DIR}/generate-keys.sh" ]; then
    echo "Generating RSA keys for Authelia..."
    chmod +x "${AUTHELIA_DIR}/generate-keys.sh"
    "${AUTHELIA_DIR}/generate-keys.sh"
else
    echo "Error: generate-keys.sh not found in ${AUTHELIA_DIR}"
    exit 1
fi

echo "Authelia setup complete!" 