// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/openchami/tokensmith/pkg/tokenservice"
)

const (
	tokensmithURL = "http://localhost:8080" // Update this to match your tokensmith service URL
	serviceName   = "example-service"
	serviceID     = "example-service-1"
)

func main() {
	// Parse command line flags
	instanceID := flag.String("instance-id", "", "OpenCHAMI instance ID")
	clusterID := flag.String("cluster-id", "", "OpenCHAMI cluster ID")
	flag.Parse()

	// Validate required flags
	if *instanceID == "" || *clusterID == "" {
		log.Fatal("Both --instance-id and --cluster-id are required")
	}

	// Create a new service client
	client := tokenservice.NewServiceClient(tokensmithURL, serviceName, serviceID, *instanceID, *clusterID)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get initial token
	log.Println("Getting initial service token...")
	if err := client.GetToken(ctx); err != nil {
		log.Fatalf("Failed to get initial token: %v", err)
	}
	log.Printf("Got token, expires at: %v\n", client.GetServiceToken().ExpiresAt)

	// Demonstrate token refresh
	log.Println("\nWaiting for token to be close to expiration...")
	time.Sleep(2 * time.Second) // In a real application, you'd wait until closer to expiration

	log.Println("Refreshing token...")
	if err := client.RefreshTokenIfNeeded(ctx); err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}
	log.Printf("Refreshed token, new expiration: %v\n", client.GetServiceToken().ExpiresAt)

	// Demonstrate calling another service with the token
	log.Println("\nCalling target service...")
	targetURL := "http://localhost:8081/protected-endpoint" // Update this to your target service URL
	if err := client.CallTargetService(ctx, targetURL); err != nil {
		log.Fatalf("Failed to call target service: %v", err)
	}
	log.Println("Successfully called target service!")
}
