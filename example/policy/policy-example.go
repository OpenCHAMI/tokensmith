package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/policy"
	"github.com/openchami/tokensmith/pkg/tokenservice"
)

func main() {
	// Example 1: Using the static policy engine
	fmt.Println("=== Static Policy Engine Example ===")
	staticExample()

	// Example 2: Using the file-based policy engine
	fmt.Println("\n=== File-Based Policy Engine Example ===")
	fileBasedExample()
}

func staticExample() {
	// Create a static policy engine configuration
	staticConfig := &policy.StaticEngineConfig{
		Name:          "example-static-engine",
		Version:       "1.0.0",
		Scopes:        []string{"read", "write", "admin"},
		Audiences:     []string{"smd", "bss", "cloud-init"},
		Permissions:   []string{"read:all", "write:all", "admin:all"},
		TokenLifetime: func() *time.Duration { d := 2 * time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"policy_engine": "static",
			"environment":   "example",
		},
	}

	// Create the static policy engine
	engine, err := policy.NewStaticEngine(staticConfig)
	if err != nil {
		log.Fatalf("Failed to create static engine: %v", err)
	}

	// Create a policy context
	ctx := context.Background()
	policyCtx := &policy.PolicyContext{
		Username: "testuser",
		Groups:   []string{"admin", "user"},
		Claims: map[string]interface{}{
			"email": "test@example.com",
			"name":  "Test User",
		},
		ClusterID:   "example-cluster",
		OpenCHAMIID: "example-openchami",
	}

	// Evaluate the policy
	decision, err := engine.EvaluatePolicy(ctx, policyCtx)
	if err != nil {
		log.Fatalf("Policy evaluation failed: %v", err)
	}

	// Print the results
	fmt.Printf("Engine: %s v%s\n", engine.GetName(), engine.GetVersion())
	fmt.Printf("Scopes: %v\n", decision.Scopes)
	fmt.Printf("Audiences: %v\n", decision.Audiences)
	fmt.Printf("Permissions: %v\n", decision.Permissions)
	if decision.TokenLifetime != nil {
		fmt.Printf("Token Lifetime: %v\n", *decision.TokenLifetime)
	}
	fmt.Printf("Additional Claims: %v\n", decision.AdditionalClaims)
}

func fileBasedExample() {
	// Create a file-based policy engine configuration
	fileBasedConfig := &policy.FileBasedEngineConfig{
		Name:           "example-file-engine",
		Version:        "1.0.0",
		ConfigPath:     "example/policy/file-based-config.json",
		ReloadInterval: func() *time.Duration { d := 5 * time.Minute; return &d }(),
	}

	// Create the file-based policy engine
	engine, err := policy.NewFileBasedEngine(fileBasedConfig)
	if err != nil {
		log.Fatalf("Failed to create file-based engine: %v", err)
	}

	// Test different user scenarios
	ctx := context.Background()

	scenarios := []struct {
		name     string
		username string
		groups   []string
		expected string
	}{
		{
			name:     "Admin user",
			username: "adminuser",
			groups:   []string{},
			expected: "admin role",
		},
		{
			name:     "Regular user",
			username: "regularuser",
			groups:   []string{},
			expected: "user role",
		},
		{
			name:     "User with admin group",
			username: "someuser",
			groups:   []string{"admins"},
			expected: "admin role",
		},
		{
			name:     "User with multiple groups",
			username: "poweruser",
			groups:   []string{"users", "operators"},
			expected: "multiple roles",
		},
		{
			name:     "Unknown user",
			username: "unknownuser",
			groups:   []string{"unknown-group"},
			expected: "default policy",
		},
	}

	for _, scenario := range scenarios {
		fmt.Printf("\n--- %s ---\n", scenario.name)

		policyCtx := &policy.PolicyContext{
			Username: scenario.username,
			Groups:   scenario.groups,
			Claims: map[string]interface{}{
				"email": fmt.Sprintf("%s@example.com", scenario.username),
			},
			ClusterID:   "example-cluster",
			OpenCHAMIID: "example-openchami",
		}

		decision, err := engine.EvaluatePolicy(ctx, policyCtx)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		fmt.Printf("User: %s, Groups: %v\n", scenario.username, scenario.groups)
		fmt.Printf("Scopes: %v\n", decision.Scopes)
		fmt.Printf("Audiences: %v\n", decision.Audiences)
		fmt.Printf("Permissions: %v\n", decision.Permissions)
		if decision.TokenLifetime != nil {
			fmt.Printf("Token Lifetime: %v\n", *decision.TokenLifetime)
		}
		if len(decision.AdditionalClaims) > 0 {
			fmt.Printf("Additional Claims: %v\n", decision.AdditionalClaims)
		}
	}
}

// Example of integrating with TokenService
func tokenServiceExample() {
	// Create a key manager (this would normally be done with proper key generation)
	keyManager := keys.NewKeyManager()

	// Create a policy engine configuration
	policyConfig := &tokenservice.PolicyEngineConfig{
		Type: tokenservice.PolicyEngineTypeStatic,
		Static: &policy.StaticEngineConfig{
			Name:        "tokenservice-static-engine",
			Version:     "1.0.0",
			Scopes:      []string{"read", "write"},
			Audiences:   []string{"smd", "bss", "cloud-init"},
			Permissions: []string{"read:basic", "write:basic"},
		},
	}

	// Create the token service configuration
	config := tokenservice.Config{
		Issuer:       "https://tokensmith.example.com",
		ClusterID:    "example-cluster",
		OpenCHAMIID:  "example-openchami",
		ProviderType: tokenservice.ProviderTypeHydra,
		PolicyEngine: policyConfig,
		// ... other configuration
	}

	// Create the token service
	service, err := tokenservice.NewTokenService(keyManager, config)
	if err != nil {
		log.Fatalf("Failed to create token service: %v", err)
	}

	fmt.Printf("Token service created with policy engine: %s v%s\n",
		service.PolicyEngine.GetName(),
		service.PolicyEngine.GetVersion())
}
