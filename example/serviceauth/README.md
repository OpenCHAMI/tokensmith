# Service Authentication Example

This example demonstrates how to implement service-to-service authentication using the tokensmith service. It shows how a service can:
1. Obtain a service token from tokensmith
2. Automatically refresh the token when needed
3. Use the token to authenticate with other services

## Prerequisites

- Go 1.16 or later
- A running tokensmith service (default: `http://localhost:8080`)
- A target service that accepts service tokens (for demonstration)

## Configuration

Before running the example, you need to:

1. Ensure the tokensmith service is running and accessible
2. Update the following constants in `main.go` if needed:
   ```go
   const (
       tokensmithURL = "http://localhost:8080" // Your tokensmith service URL
       serviceName   = "example-service"        // Your service name
       serviceID     = "example-service-1"      // Your service ID
   )
   ```
3. Update the `targetURL` in the main function to point to your target service:
   ```go
   targetURL := "http://localhost:8081/protected-endpoint"
   ```

## Running the Example

1. Navigate to the example directory:
   ```bash
   cd example/serviceauth
   ```

2. Run the example with required OpenCHAMI parameters:
   ```bash
   go run main.go --instance-id="openchami-instance-1" --cluster-id="cluster-1"
   ```

The example will:
1. Get an initial service token from tokensmith with OpenCHAMI-specific claims
2. Display the token expiration time
3. Demonstrate token refresh functionality
4. Use the token to call another service

## OpenCHAMI Integration

This example includes OpenCHAMI-specific custom claims in the service tokens:

- `instance_id`: The OpenCHAMI instance identifier
- `cluster_id`: The OpenCHAMI cluster identifier
- `iss`: The tokensmith service URI as the issuer

These claims are passed via headers:
- `X-Instance-ID`: OpenCHAMI instance identifier
- `X-Cluster-ID`: OpenCHAMI cluster identifier

The tokensmith service will include these claims in the generated JWT tokens, which can be used for:
- Service identification within OpenCHAMI
- Cluster-specific authorization
- Instance-level tracking and monitoring

## Code Structure

The example consists of a `ServiceClient`