<!--
Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC

SPDX-License-Identifier: MIT
-->

# Service Authentication Example

This example demonstrates TokenSmith service-to-service authentication using `pkg/tokenservice`.

It shows how a caller service can:

1. redeem a startup bootstrap token for an access token plus refresh token
2. refresh tokens automatically when they approach expiry
3. call another service with a TokenSmith-issued bearer token

## Prerequisites

- Go 1.16 or later
- a running TokenSmith service (default: `http://localhost:8080`)
- a target service that accepts TokenSmith-issued bearer tokens
- a one-time bootstrap token minted with `tokensmith bootstrap-token create`

## Configuration

Before running the example:

1. ensure the TokenSmith service is running and reachable
2. mint a bootstrap token for this caller service from the same TokenSmith runtime context:

```bash
BOOTSTRAP_TOKEN=$(podman exec tokensmith \
    tokensmith bootstrap-token create \
        --subject example-service-1 \
        --audience metadata-service \
        --scopes "read" \
        --ttl 10m \
        --refresh-ttl 24h \
        --bootstrap-store /var/lib/tokensmith/bootstrap \
        --output-format json | jq -r '.bootstrap_token')
```

3. export that bootstrap token:

```bash
export TOKENSMITH_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN"
```

4. update the constants in `main.go` if needed:

```go
const (
    tokensmithURL = "http://localhost:8080"
    serviceName   = "example-service"
    serviceID     = "example-service-1"
)
```

5. update `targetURL` in `main.go` to point to the downstream service you want to call

## Running the example

```bash
cd example/serviceauth
go run main.go --instance-id="openchami-instance-1" --cluster-id="cluster-1"
```

The example will:

1. perform the initial bootstrap exchange against `POST /oauth/token`
2. print the resulting access-token expiry
3. run a refresh check
4. call the target service with `Authorization: Bearer <token>`

### Expected example logs

Successful run:

```text
Getting initial service token...
Got token, expires at: 2026-04-14 22:49:10 +0000 UTC

Waiting for token to be close to expiration...
Refreshing token...
Refreshed token, new expiration: 2026-04-14 23:49:10 +0000 UTC

Calling target service...
Successfully called target service!
```

Common failure output:

```text
Failed to get initial token: bootstrap token exchange failed after 5 attempts: failed to get token: status=400, body={"error":"invalid_grant","error_description":"The provided token is invalid or has already been used"}
```

```text
Failed to get initial token: missing bootstrap token: set TOKENSMITH_BOOTSTRAP_TOKEN or WithBootstrapToken
```

If this example succeeds, TokenSmith should log a matching successful bootstrap exchange and later refresh rotation.

## What the client actually does

The example uses `pkg/tokenservice.ServiceClient`.

Current behavior:

- initial exchange uses RFC 8693 form data at `POST /oauth/token`
- refresh uses `grant_type=refresh_token` at `POST /oauth/token`
- the client stores the current access token, refresh token, and expiry timestamps in memory
- `CallTargetService()` refreshes first if the token is near expiry

The direct service-token HTTP contract is documented in `docs/http-endpoints.md`.

## OpenCHAMI-specific claims

TokenSmith-issued service tokens include OpenCHAMI-specific claims configured on the TokenSmith server, including:

- `openchami_id`
- `cluster_id`
- `iss`

## Security notes

- bootstrap tokens are one-time use
- reusing a consumed bootstrap token fails
- refresh tokens are rotated on every successful use
- replaying an old refresh token revokes the refresh-token family
- use HTTPS for real deployments
- use durable RFC 8693 stores on the TokenSmith server if you need restart-safe replay protection

## Integration pattern for your own services

1. import the package:

```go
import "github.com/openchami/tokensmith/pkg/tokenservice"
```

2. create the client:

```go
client := tokenservice.NewServiceClientWithOptions(
    "https://your-tokensmith-service",
    "your-service-name",
    "your-service-id",
    "your-instance-id",
    "your-cluster-id",
    tokenservice.WithBootstrapToken(os.Getenv("TOKENSMITH_BOOTSTRAP_TOKEN")),
    tokenservice.WithTargetService("metadata-service"),
)
```

3. initialize once at startup:

```go
if err := client.Initialize(ctx); err != nil {
    return err
}

go client.StartAutoRefresh(ctx)
```

4. use the access token when calling downstream services:

```go
if err := client.CallTargetService(ctx, "https://api.example.com/protected"); err != nil {
    return err
}
```

See also:

- `docs/internal-service-auth.md`
- `docs/http-endpoints.md`
