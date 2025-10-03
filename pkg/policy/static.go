// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policy provides a static policy engine implementation that always returns
// the same hardcoded scopes, audiences, and permissions regardless of user context.
// This implementation serves as an example and can be used for simple deployments
// where all users should receive the same permissions.
package policy

import (
	"context"
	"fmt"
	"time"
)

// StaticEngine is a policy engine that always returns the same hardcoded policy decision.
// This is useful for simple deployments where all users should receive the same permissions.
type StaticEngine struct {
	name             string
	version          string
	scopes           []string
	audiences        []string
	permissions      []string
	tokenLifetime    *time.Duration
	additionalClaims map[string]interface{}
}

// StaticEngineConfig holds the configuration for the static policy engine
type StaticEngineConfig struct {
	// Name is the human-readable name for this policy engine
	Name string `json:"name"`

	// Version is the version of this policy engine
	Version string `json:"version"`

	// Scopes are the OAuth 2.0 scopes to grant to all users
	Scopes []string `json:"scopes"`

	// Audiences are the intended recipients of the token
	Audiences []string `json:"audiences"`

	// Permissions are specific permissions to grant to all users
	Permissions []string `json:"permissions"`

	// TokenLifetime is the duration for which tokens should be valid
	// If not set, a default lifetime will be used
	TokenLifetime *time.Duration `json:"token_lifetime,omitempty"`

	// AdditionalClaims are custom claims to be included in all tokens
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`
}

// DefaultStaticConfig returns a default configuration for the static policy engine
func DefaultStaticConfig() *StaticEngineConfig {
	return &StaticEngineConfig{
		Name:        "static-policy-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read", "write"},
		Audiences:   []string{"smd", "bss", "cloud-init"},
		Permissions: []string{"read:basic", "write:basic"},
		TokenLifetime: func() *time.Duration {
			d := time.Hour
			return &d
		}(),
		AdditionalClaims: map[string]interface{}{
			"policy_engine":  "static",
			"policy_version": "1.0.0",
		},
	}
}

// NewStaticEngine creates a new static policy engine with the given configuration
func NewStaticEngine(config *StaticEngineConfig) (*StaticEngine, error) {
	if config == nil {
		config = DefaultStaticConfig()
	}

	// Validate configuration
	if err := validateStaticConfig(config); err != nil {
		return nil, fmt.Errorf("invalid static policy engine configuration: %w", err)
	}

	engine := &StaticEngine{
		name:             config.Name,
		version:          config.Version,
		scopes:           make([]string, len(config.Scopes)),
		audiences:        make([]string, len(config.Audiences)),
		permissions:      make([]string, len(config.Permissions)),
		tokenLifetime:    config.TokenLifetime,
		additionalClaims: make(map[string]interface{}),
	}

	// Copy slices to avoid external modifications
	copy(engine.scopes, config.Scopes)
	copy(engine.audiences, config.Audiences)
	copy(engine.permissions, config.Permissions)

	// Copy additional claims
	for k, v := range config.AdditionalClaims {
		engine.additionalClaims[k] = v
	}

	return engine, nil
}

// EvaluatePolicy always returns the same hardcoded policy decision
func (e *StaticEngine) EvaluatePolicy(ctx context.Context, policyCtx *PolicyContext) (*PolicyDecision, error) {
	// Create a copy of the decision to avoid external modifications
	decision := &PolicyDecision{
		Scopes:           make([]string, len(e.scopes)),
		Audiences:        make([]string, len(e.audiences)),
		Permissions:      make([]string, len(e.permissions)),
		TokenLifetime:    e.tokenLifetime,
		AdditionalClaims: make(map[string]interface{}),
	}

	copy(decision.Scopes, e.scopes)
	copy(decision.Audiences, e.audiences)
	copy(decision.Permissions, e.permissions)

	// Copy additional claims
	for k, v := range e.additionalClaims {
		decision.AdditionalClaims[k] = v
	}

	return decision, nil
}

// GetName returns the name of this policy engine (for logging purposes)
func (e *StaticEngine) GetName() string {
	return e.name
}

// GetVersion returns the version of this policy engine (for logging purposes)
func (e *StaticEngine) GetVersion() string {
	return e.version
}

// ValidateConfiguration validates the static policy engine configuration
func (e *StaticEngine) ValidateConfiguration() error {
	return validateStaticConfig(&StaticEngineConfig{
		Name:             e.name,
		Version:          e.version,
		Scopes:           e.scopes,
		Audiences:        e.audiences,
		Permissions:      e.permissions,
		TokenLifetime:    e.tokenLifetime,
		AdditionalClaims: e.additionalClaims,
	})
}

// validateStaticConfig validates a static policy engine configuration
func validateStaticConfig(config *StaticEngineConfig) error {
	result := ValidateStaticEngineConfig(config)
	if !result.IsValid() {
		// Return the first error for backward compatibility
		if len(result.Errors) > 0 {
			return result.Errors[0]
		}
		return fmt.Errorf("configuration validation failed")
	}
	return nil
}
