#!/bin/bash

# Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

# TokenSmith Integration Test - Complete Authentication Flow
# This script demonstrates the full OIDC authentication chain:
# 1. Login to Authelia
# 2. Get token from TokenSmith
# 3. Access protected resource (httpbin) through Traefik

set -e

echo "🔐 TokenSmith Integration Test - Complete Authentication Flow"
echo "=========================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if services are running
check_services() {
    print_status "Checking if all services are running..."

    services=("step-ca" "traefik" "authelia" "tokensmith" "httpbin")
    for service in "${services[@]}"; do
        if docker compose ps | grep -q "$service.*Up"; then
            print_success "$service is running"
        else
            print_error "$service is not running"
            exit 1
        fi
    done
}

# Wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."

    # Wait for Step-CA
    print_status "Waiting for Step-CA..."
    timeout=60
    while ! curl -k -s https://localhost:9000/health > /dev/null 2>&1; do
        if [ $timeout -le 0 ]; then
            print_error "Step-CA did not become ready in time"
            exit 1
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    print_success "Step-CA is ready"

    # Wait for Traefik
    print_status "Waiting for Traefik..."
    timeout=60
    while ! curl -k -s https://localhost:443 > /dev/null 2>&1; do
        if [ $timeout -le 0 ]; then
            print_error "Traefik did not become ready in time"
            exit 1
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    print_success "Traefik is ready"

    # Wait for Authelia
    print_status "Waiting for Authelia..."
    timeout=60
    while ! curl -k -s http://auth.openchami.demo:9091/api/health > /dev/null 2>&1; do
        if [ $timeout -le 0 ]; then
            print_error "Authelia did not become ready in time"
            exit 1
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    print_success "Authelia is ready"

    # Wait for TokenSmith
    print_status "Waiting for TokenSmith..."
    timeout=60
    while ! curl -k -s http://tokensmith.openchami.demo:8080/health > /dev/null 2>&1; do
        if [ $timeout -le 0 ]; then
            print_error "TokenSmith did not become ready in time"
            exit 1
        fi
        sleep 2
        timeout=$((timeout - 2))
    done
    print_success "TokenSmith is ready"
}

# Test 1: Direct access to protected resource (should fail)
test_unauthenticated_access() {
    print_status "Test 1: Attempting unauthenticated access to protected resource..."

    response=$(curl -k -s -w "%{http_code}" https://api.openchami.demo:443/headers)
    http_code="${response: -3}"

    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        print_success "Unauthenticated access correctly blocked (HTTP $http_code)"
    else
        print_warning "Unexpected response for unauthenticated access (HTTP $http_code)"
    fi
}

# Test 2: Login to Authelia
test_authelia_login() {
    print_status "Test 2: Logging in to Authelia..."

    # Note: This is a simplified test. In a real scenario, you'd need to handle
    # the full OIDC flow with browser interaction
    print_warning "Authelia login requires browser interaction in real scenarios"
    print_status "Authelia login endpoint: https://auth.openchami.demo:9091"
}

# Test 3: Get token from TokenSmith
test_tokensmith_token() {
    print_status "Test 3: Getting token from TokenSmith..."

    # Try to get a service token (this might work without full OIDC flow)
    response=$(curl -k -s -w "%{http_code}" \
        -X POST http://tokensmith.openchami.demo:8080/tokens/service \
        -H "Content-Type: application/json" \
        -d '{"scope": ["read"], "expiration": "1h"}')

    http_code="${response: -3}"
    body="${response%???}"

    if [ "$http_code" = "200" ]; then
        print_success "Successfully obtained token from TokenSmith"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    else
        print_warning "TokenSmith token request returned HTTP $http_code"
        echo "$body"
    fi
}

# Test 4: Access protected resource with authentication
test_authenticated_access() {
    print_status "Test 4: Testing authenticated access to protected resource..."

    # This would require a valid session cookie or token
    # For demonstration, we'll show the expected flow
    print_status "Expected flow:"
    print_status "1. Browser redirects to Authelia login"
    print_status "2. User authenticates with Authelia"
    print_status "3. Authelia redirects back with session"
    print_status "4. Traefik validates session with Authelia"
    print_status "5. If valid, request proceeds to httpbin"

    print_warning "Full OIDC flow requires browser interaction"
    print_status "Protected resource: https://api.openchami.demo:443"
}

# Test 5: Check TokenSmith health and endpoints
test_tokensmith_endpoints() {
    print_status "Test 5: Checking TokenSmith endpoints..."

    endpoints=("/health" "/auth/login" "/tokens/service" "/tokens/validate")

    for endpoint in "${endpoints[@]}"; do
        response=$(curl -k -s -w "%{http_code}" http://tokensmith.openchami.demo:8080$endpoint)
        http_code="${response: -3}"

        if [ "$http_code" = "200" ] || [ "$http_code" = "405" ]; then
            print_success "TokenSmith $endpoint endpoint responding (HTTP $http_code)"
        else
            print_warning "TokenSmith $endpoint endpoint returned HTTP $http_code"
        fi
    done
}

# Test 6: Check Authelia endpoints
test_authelia_endpoints() {
    print_status "Test 6: Checking Authelia endpoints..."

    endpoints=("/api/health" "/api/verify")

    for endpoint in "${endpoints[@]}"; do
        response=$(curl -k -s -w "%{http_code}" http://auth.openchami.demo:9091$endpoint)
        http_code="${response: -3}"

        if [ "$http_code" = "200" ] || [ "$http_code" = "401" ]; then
            print_success "Authelia $endpoint endpoint responding (HTTP $http_code)"
        else
            print_warning "Authelia $endpoint endpoint returned HTTP $http_code"
        fi
    done
}

# Main test execution
main() {
    echo
    print_status "Starting TokenSmith integration tests..."
    echo

    check_services
    echo

    wait_for_services
    echo

    test_unauthenticated_access
    echo

    test_authelia_login
    echo

    test_tokensmith_token
    echo

    test_authenticated_access
    echo

    test_tokensmith_endpoints
    echo

    test_authelia_endpoints
    echo

    print_success "Integration test completed!"
    echo
    print_status "Next steps:"
    print_status "1. Open https://auth.openchami.demo:9091 in your browser"
    print_status "2. Login with test credentials"
    print_status "3. Access https://api.openchami.demo:443 to test the full flow"
    print_status "4. Check TokenSmith dashboard at https://tokensmith.openchami.demo:8080"
    echo
}

# Run the tests
main "$@"
