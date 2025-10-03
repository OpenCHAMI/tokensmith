#!/bin/bash

# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

# Generate password hash for Authelia user database
# This script uses Authelia's built-in hash-password command

set -e

echo "Generating password hash for Authelia..."

# Default password for testing
PASSWORD="password"

echo "Using password: $PASSWORD"
echo ""

# Use Authelia's hash-password command
# We'll run this in a temporary container
HASH=$(docker run --rm authelia/authelia:latest authelia crypto hash generate argon2 --password "$PASSWORD")

echo "Generated hash:"
echo "$HASH"
echo ""

# Update the users_database.yml file
USERS_FILE="config/users_database.yml"

if [ -f "$USERS_FILE" ]; then
    echo "Updating $USERS_FILE..."

    # Create a backup
    cp "$USERS_FILE" "${USERS_FILE}.backup"

    # Update the password hash
    sed -i.bak "s|password: \".*\"|password: \"$HASH\"|" "$USERS_FILE"

    echo "Password hash updated successfully!"
    echo "Backup saved as ${USERS_FILE}.backup"
else
    echo "Error: $USERS_FILE not found"
    exit 1
fi

echo ""
echo "You can now use the password '$PASSWORD' to log in as admin@example.com"
