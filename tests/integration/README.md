<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# TokenSmith Integration Testing

This directory contains a complete Docker Compose environment for testing TokenSmith with all its dependencies. The setup includes a Certificate Authority (Step-CA), reverse proxy (Traefik), authentication service (Authelia), TokenSmith, and a protected resource (httpbin).

## Prerequisites

- Docker and Docker Compose installed
- At least 4GB of available RAM
- Ports 80, 443, 8080, and 9000 available

## Quick Start

### 1. Build the TokenSmith Container

First, build the TokenSmith container from the project root:

```bash
# Navigate to the project root
cd ../../

# Build the container without publishing
goreleaser release --snapshot --skip=publish --rm-dist
```

**What this does:** This command builds a Docker image from the project root. The `--snapshot` flag creates a development build, and `--skip=publish` prevents publishing to a registry.

### 2. Start the Integration Environment

```bash
# Navigate to the integration test directory
cd tests/integration

# Create necessary directories
mkdir -p certificates step-ca/certs step-ca/config step-ca/data step-ca/secrets

# Start all services
docker compose up -d
```

**What this does:**
- Creates required directories for certificates and configuration
- Starts all services in detached mode (`-d` flag)
- The services will initialize in the correct order due to dependencies

### 3. Wait for Services to Initialize

```bash
# Check service status
docker compose ps

# Watch logs for initialization
docker compose logs -f
```

**What this does:**
- `docker compose ps` shows the status of all services
- `docker compose logs -f` follows the logs in real-time to see initialization progress
- Press `Ctrl+C` to stop following logs

### 4. Verify Services Are Running

```bash
# Check if Step-CA is healthy
curl -k https://localhost:9000/health

# Check if Traefik is responding
curl -k https://localhost:443

# Check if TokenSmith is accessible
curl -k https://localhost:8080/health
```

**What this does:** These commands test if the key services are responding properly. The `-k` flag skips SSL certificate verification since we're using a self-signed CA.

## Service Architecture

The integration environment consists of five main services:

### Step-CA (Certificate Authority)
- **Port:** 9000
- **Purpose:** Issues TLS certificates for all services
- **URL:** https://step-ca.openchami.demo:9000
- **What it does:** Provides a private certificate authority that issues valid certificates for the test domain

### Traefik (Reverse Proxy)
- **Ports:** 80, 443
- **Purpose:** Routes traffic and handles TLS termination
- **URLs:** https://auth.openchami.demo, https://tokensmith.openchami.demo, https://api.openchami.demo
- **What it does:** Acts as a reverse proxy, automatically obtains certificates from Step-CA, and routes traffic to the appropriate services

### Authelia (Authentication)
- **Port:** 9091
- **Purpose:** Provides user authentication and OIDC provider
- **URL:** https://auth.openchami.demo:9091
- **What it does:** Handles user login, MFA, session management, and acts as an OIDC provider for TokenSmith

### TokenSmith
- **Port:** 8080
- **Purpose:** The main token service being tested
- **URL:** https://tokensmith.openchami.demo:8080
- **What it does:** Issues and validates tokens, integrates with Authelia for OIDC authentication

### httpbin (Protected Resource)
- **Port:** 80 (internal)
- **Purpose:** Test API that requires authentication
- **URL:** https://api.openchami.demo:443
- **What it does:** Provides a simple HTTP API for testing authenticated access

## Complete Authentication Flow

This integration demonstrates the full OIDC authentication chain:

1. **User accesses protected resource** → https://api.openchami.demo:443
2. **Traefik forwards to Authelia** → https://auth.openchami.demo:9091/api/verify
3. **User authenticates with Authelia** → Login page
4. **Authelia redirects to TokenSmith** → OIDC authorization flow
5. **TokenSmith issues token** → JWT token with claims
6. **User accesses resource with token** → Authenticated API access

## Testing the Setup

### 1. Add Host Entries

Add the following to your `/etc/hosts` file:
```
127.0.0.1 tokensmith.openchami.demo
127.0.0.1 auth.openchami.demo
127.0.0.1 api.openchami.demo
```

### 2. Run the Integration Test

```bash
# Make the test script executable
chmod +x test-auth-flow.sh

# Run the complete authentication flow test
./test-auth-flow.sh
```

### 3. Manual Testing

#### Test Unauthenticated Access
```bash
# This should redirect to login
curl -k https://api.openchami.demo:443/headers
```

#### Test Authelia Login
1. Open https://auth.openchami.demo:9091 in your browser
2. Login with test credentials (see users_database.yml)
3. You should be redirected back to the protected resource

#### Test TokenSmith Endpoints
```bash
# Check TokenSmith health
curl -k https://tokensmith.openchami.demo:8080/health

# Try to get a service token
curl -k -X POST https://tokensmith.openchami.demo:8080/tokens/service \
  -H "Content-Type: application/json" \
  -d '{"scope": ["read"], "expiration": "1h"}'
```

### 4. Browser Testing

1. **Access protected resource:** https://api.openchami.demo:443
2. **You'll be redirected to:** https://auth.openchami.demo:9091
3. **Login with credentials:** admin/password
4. **You'll be redirected to:** https://tokensmith.openchami.demo:8080/auth/login
5. **Complete OIDC flow** and get redirected back to the API
6. **Access the API** with your authenticated session

## Configuration Files

### TokenSmith Configuration
Located at `tokensmith/config/config.json`:
```json
{
  "group_scopes": {
    "admin": ["admin", "read", "write"],
    "operator": ["read", "write"],
    "viewer": ["read"]
  },
  "service_token": {
    "allowed_scopes": ["admin", "read", "write"],
    "expiration": "1h"
  }
}
```

### Authelia Configuration
Located at `authelia/config/configuration.yml`:
- Configures OIDC provider for TokenSmith
- Sets up user authentication backend
- Defines access control policies
- Configures session management

### Test Users
Located at `authelia/config/users_database.yml`:
- **admin/password** - Administrator user
- **user/password** - Regular user

## Troubleshooting

### Common Issues

#### 1. Certificate Issues
```bash
# Check Step-CA logs
docker compose logs step-ca

# Restart certificate generation
docker compose restart step-ca
```

#### 2. Service Not Starting
```bash
# Check all service logs
docker compose logs

# Restart all services
docker compose down
docker compose up -d
```

#### 3. Authentication Flow Issues
```bash
# Check Authelia logs
docker compose logs authelia

# Check TokenSmith logs
docker compose logs tokensmith

# Verify OIDC configuration
curl -k https://auth.openchami.demo:9091/.well-known/openid_configuration
```

### Debugging Commands

```bash
# View real-time logs for all services
docker compose logs -f

# View logs for a specific service
docker compose logs -f tokensmith

# Check service health
docker compose ps

# Access a service container
docker compose exec tokensmith sh

# View network configuration
docker network ls
docker network inspect integration_tokensmith-network
```

## Cleanup

```bash
# Stop all services
docker compose down

# Remove volumes (this will delete all data)
docker compose down -v

# Remove images
docker rmi ghcr.io/openchami/tokensmith:0.0-amd64
```

## Security Notes

- This is a **testing environment** with simplified security
- Passwords and secrets are hardcoded for testing
- TLS certificates are self-signed
- Do not use this configuration in production

## Next Steps

1. **Customize Configuration:** Modify the config files to test different scenarios
2. **Add Integration Tests:** Create automated tests using the API endpoints
3. **Scale Testing:** Test with multiple concurrent users
4. **Security Testing:** Verify token validation and access controls
5. **Production Setup:** Adapt the configuration for production use

For more information about TokenSmith, see the main [README.md](../../README.md) in the project root.
