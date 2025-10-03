// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policy provides a file-based policy engine implementation that reads
// policy configuration from a file on disk. This implementation supports role-based
// access control where users can be mapped to multiple roles, and each role has
// associated scopes, audiences, and permissions.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileBasedEngine is a policy engine that reads policy configuration from a file.
// It supports role-based access control where users can be mapped to multiple roles.
type FileBasedEngine struct {
	name        string
	version     string
	configPath  string
	config      *FileBasedConfig
	lastModTime time.Time
	mu          sync.RWMutex
}

// FileBasedConfig represents the configuration structure for the file-based policy engine
type FileBasedConfig struct {
	// Version is the configuration file version
	Version string `json:"version"`

	// DefaultPolicy is the policy applied when no specific role matches
	DefaultPolicy *PolicyDecision `json:"default_policy"`

	// Roles define the available roles and their associated permissions
	Roles map[string]*RolePolicy `json:"roles"`

	// UserRoleMappings define which roles each user has access to
	UserRoleMappings map[string][]string `json:"user_role_mappings"`

	// GroupRoleMappings define which roles each group has access to
	GroupRoleMappings map[string][]string `json:"group_role_mappings"`
}

// RolePolicy defines the policy for a specific role
type RolePolicy struct {
	// Name is the human-readable name of the role
	Name string `json:"name"`

	// Description is a description of what this role allows
	Description string `json:"description"`

	// Scopes are the OAuth 2.0 scopes granted to this role
	Scopes []string `json:"scopes"`

	// Audiences are the intended recipients of tokens for this role
	Audiences []string `json:"audiences"`

	// Permissions are specific permissions granted to this role
	Permissions []string `json:"permissions"`

	// TokenLifetime is the duration for which tokens should be valid for this role
	TokenLifetime *time.Duration `json:"token_lifetime,omitempty"`

	// AdditionalClaims are custom claims to be included in tokens for this role
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`
}

// FileBasedEngineConfig holds the configuration for the file-based policy engine
type FileBasedEngineConfig struct {
	// Name is the human-readable name for this policy engine
	Name string `json:"name"`

	// Version is the version of this policy engine
	Version string `json:"version"`

	// ConfigPath is the path to the policy configuration file
	ConfigPath string `json:"config_path"`

	// ReloadInterval is how often to check for configuration file changes
	// If not set, the file is only loaded once at startup
	ReloadInterval *time.Duration `json:"reload_interval,omitempty"`
}

// FileBasedConfigWithStringDurations is used for JSON unmarshaling to handle string durations
type FileBasedConfigWithStringDurations struct {
	Version           string                           `json:"version"`
	DefaultPolicy     *PolicyDecisionWithString        `json:"default_policy"`
	Roles             map[string]*RolePolicyWithString `json:"roles"`
	UserRoleMappings  map[string][]string              `json:"user_role_mappings"`
	GroupRoleMappings map[string][]string              `json:"group_role_mappings"`
}

// PolicyDecisionWithString handles string durations during unmarshaling
type PolicyDecisionWithString struct {
	Scopes           []string               `json:"scopes"`
	Audiences        []string               `json:"audiences"`
	Permissions      []string               `json:"permissions"`
	TokenLifetimeStr string                 `json:"token_lifetime,omitempty"`
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`
}

// RolePolicyWithString handles string durations during unmarshaling
type RolePolicyWithString struct {
	Name             string                 `json:"name"`
	Description      string                 `json:"description"`
	Scopes           []string               `json:"scopes"`
	Audiences        []string               `json:"audiences"`
	Permissions      []string               `json:"permissions"`
	TokenLifetimeStr string                 `json:"token_lifetime,omitempty"`
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`
}

// DefaultFileBasedConfig returns a default configuration for the file-based policy engine
func DefaultFileBasedConfig() *FileBasedEngineConfig {
	return &FileBasedEngineConfig{
		Name:       "file-based-policy-engine",
		Version:    "1.0.0",
		ConfigPath: "/etc/tokensmith/policy.json",
		ReloadInterval: func() *time.Duration {
			d := 5 * time.Minute
			return &d
		}(),
	}
}

// convertStringDurationsToFileBasedConfig converts a config with string durations to proper FileBasedConfig
func convertStringDurationsToFileBasedConfig(configWithStrings *FileBasedConfigWithStringDurations) (*FileBasedConfig, error) {
	config := &FileBasedConfig{
		Version:           configWithStrings.Version,
		UserRoleMappings:  configWithStrings.UserRoleMappings,
		GroupRoleMappings: configWithStrings.GroupRoleMappings,
		Roles:             make(map[string]*RolePolicy),
	}

	// Convert default policy
	if configWithStrings.DefaultPolicy != nil {
		defaultPolicy, err := convertPolicyDecisionWithString(configWithStrings.DefaultPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to convert default policy: %w", err)
		}
		config.DefaultPolicy = defaultPolicy
	}

	// Convert roles
	for roleName, rolePolicyWithString := range configWithStrings.Roles {
		rolePolicy, err := convertRolePolicyWithString(rolePolicyWithString)
		if err != nil {
			return nil, fmt.Errorf("failed to convert role policy '%s': %w", roleName, err)
		}
		config.Roles[roleName] = rolePolicy
	}

	return config, nil
}

// convertPolicyDecisionWithString converts a PolicyDecisionWithString to PolicyDecision
func convertPolicyDecisionWithString(pdWithString *PolicyDecisionWithString) (*PolicyDecision, error) {
	pd := &PolicyDecision{
		Scopes:           pdWithString.Scopes,
		Audiences:        pdWithString.Audiences,
		Permissions:      pdWithString.Permissions,
		AdditionalClaims: pdWithString.AdditionalClaims,
	}

	if pdWithString.TokenLifetimeStr != "" {
		duration, err := time.ParseDuration(pdWithString.TokenLifetimeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid token_lifetime '%s': %w", pdWithString.TokenLifetimeStr, err)
		}
		pd.TokenLifetime = &duration
	}

	return pd, nil
}

// convertRolePolicyWithString converts a RolePolicyWithString to RolePolicy
func convertRolePolicyWithString(rpWithString *RolePolicyWithString) (*RolePolicy, error) {
	rp := &RolePolicy{
		Name:             rpWithString.Name,
		Description:      rpWithString.Description,
		Scopes:           rpWithString.Scopes,
		Audiences:        rpWithString.Audiences,
		Permissions:      rpWithString.Permissions,
		AdditionalClaims: rpWithString.AdditionalClaims,
	}

	if rpWithString.TokenLifetimeStr != "" {
		duration, err := time.ParseDuration(rpWithString.TokenLifetimeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid token_lifetime '%s': %w", rpWithString.TokenLifetimeStr, err)
		}
		rp.TokenLifetime = &duration
	}

	return rp, nil
}

// NewFileBasedEngine creates a new file-based policy engine with the given configuration
func NewFileBasedEngine(config *FileBasedEngineConfig) (*FileBasedEngine, error) {
	if config == nil {
		config = DefaultFileBasedConfig()
	}

	// Validate configuration
	if err := validateFileBasedEngineConfig(config); err != nil {
		return nil, fmt.Errorf("invalid file-based policy engine configuration: %w", err)
	}

	engine := &FileBasedEngine{
		name:       config.Name,
		version:    config.Version,
		configPath: config.ConfigPath,
	}

	// Load initial configuration
	if err := engine.loadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load initial configuration: %w", err)
	}

	// Start reload goroutine if reload interval is specified
	if config.ReloadInterval != nil {
		go engine.startReloadLoop(*config.ReloadInterval)
	}

	return engine, nil
}

// EvaluatePolicy determines the policy decision based on user context and role mappings
func (e *FileBasedEngine) EvaluatePolicy(ctx context.Context, policyCtx *PolicyContext) (*PolicyDecision, error) {
	// Reload config if needed
	if err := e.reloadConfigIfNeeded(); err != nil {
		// Log error but continue with current config
		// In production, you might want to use a proper logger
		fmt.Printf("Warning: failed to reload config: %v\n", err)
	}

	e.mu.RLock()
	config := e.config
	e.mu.RUnlock()

	if config == nil {
		return DefaultPolicyDecision(), nil
	}

	// Determine user roles
	roles := e.determineUserRoles(policyCtx, config)

	// If no roles found, use default policy
	if len(roles) == 0 {
		if config.DefaultPolicy != nil {
			return e.copyPolicyDecision(config.DefaultPolicy), nil
		}
		return DefaultPolicyDecision(), nil
	}

	// Collect policy decisions from all roles
	var decisions []*PolicyDecision
	for _, roleName := range roles {
		if rolePolicy, exists := config.Roles[roleName]; exists {
			decision := &PolicyDecision{
				Scopes:           rolePolicy.Scopes,
				Audiences:        rolePolicy.Audiences,
				Permissions:      rolePolicy.Permissions,
				TokenLifetime:    rolePolicy.TokenLifetime,
				AdditionalClaims: rolePolicy.AdditionalClaims,
			}
			decisions = append(decisions, decision)
		}
	}

	// Merge all role decisions
	return MergePolicyDecisions(decisions...), nil
}

// GetName returns the name of this policy engine (for logging purposes)
func (e *FileBasedEngine) GetName() string {
	return e.name
}

// GetVersion returns the version of this policy engine (for logging purposes)
func (e *FileBasedEngine) GetVersion() string {
	return e.version
}

// ValidateConfiguration validates the file-based policy engine configuration
func (e *FileBasedEngine) ValidateConfiguration() error {
	e.mu.RLock()
	config := e.config
	e.mu.RUnlock()

	if config == nil {
		return fmt.Errorf("configuration not loaded")
	}

	return validateFileBasedConfig(config)
}

// determineUserRoles determines which roles a user has based on their context
func (e *FileBasedEngine) determineUserRoles(policyCtx *PolicyContext, config *FileBasedConfig) []string {
	var roles []string

	// Check user-specific role mappings
	if userRoles, exists := config.UserRoleMappings[policyCtx.Username]; exists {
		roles = append(roles, userRoles...)
	}

	// Check group-based role mappings
	for _, group := range policyCtx.Groups {
		if groupRoles, exists := config.GroupRoleMappings[group]; exists {
			roles = append(roles, groupRoles...)
		}
	}

	// Remove duplicates
	roleSet := make(map[string]bool)
	var uniqueRoles []string
	for _, role := range roles {
		if !roleSet[role] {
			roleSet[role] = true
			uniqueRoles = append(uniqueRoles, role)
		}
	}

	return uniqueRoles
}

// loadConfig loads the policy configuration from the file
func (e *FileBasedEngine) loadConfig() error {
	data, err := os.ReadFile(e.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// First try to unmarshal with string durations
	var configWithStrings FileBasedConfigWithStringDurations
	if err := json.Unmarshal(data, &configWithStrings); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Convert string durations to proper time.Duration values
	config, err := convertStringDurationsToFileBasedConfig(&configWithStrings)
	if err != nil {
		return fmt.Errorf("failed to convert configuration: %w", err)
	}

	// Validate the loaded configuration
	if err := validateFileBasedConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	e.mu.Lock()
	e.config = config
	e.mu.Unlock()

	// Update last modification time
	if stat, err := os.Stat(e.configPath); err == nil {
		e.lastModTime = stat.ModTime()
	}

	return nil
}

// reloadConfigIfNeeded checks if the config file has been modified and reloads if necessary
func (e *FileBasedEngine) reloadConfigIfNeeded() error {
	stat, err := os.Stat(e.configPath)
	if err != nil {
		return err
	}

	if stat.ModTime().After(e.lastModTime) {
		return e.loadConfig()
	}

	return nil
}

// startReloadLoop starts a goroutine that periodically checks for config file changes
func (e *FileBasedEngine) startReloadLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		if err := e.reloadConfigIfNeeded(); err != nil {
			// Log error but continue
			fmt.Printf("Warning: failed to reload config: %v\n", err)
		}
	}
}

// copyPolicyDecision creates a deep copy of a policy decision
func (e *FileBasedEngine) copyPolicyDecision(decision *PolicyDecision) *PolicyDecision {
	if decision == nil {
		return nil
	}

	policyCopy := &PolicyDecision{
		Scopes:           make([]string, len(decision.Scopes)),
		Audiences:        make([]string, len(decision.Audiences)),
		Permissions:      make([]string, len(decision.Permissions)),
		TokenLifetime:    decision.TokenLifetime,
		AdditionalClaims: make(map[string]interface{}),
	}

	copy(policyCopy.Scopes, decision.Scopes)
	copy(policyCopy.Audiences, decision.Audiences)
	copy(policyCopy.Permissions, decision.Permissions)

	for k, v := range decision.AdditionalClaims {
		policyCopy.AdditionalClaims[k] = v
	}

	return policyCopy
}

// validateFileBasedEngineConfig validates a file-based policy engine configuration
func validateFileBasedEngineConfig(config *FileBasedEngineConfig) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	if config.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if config.Version == "" {
		return fmt.Errorf("version cannot be empty")
	}

	if config.ConfigPath == "" {
		return fmt.Errorf("config_path cannot be empty")
	}

	// Check if config file exists
	if _, err := os.Stat(config.ConfigPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", config.ConfigPath)
	}

	if config.ReloadInterval != nil && *config.ReloadInterval <= 0 {
		return fmt.Errorf("reload_interval must be positive")
	}

	return nil
}

// validateFileBasedConfig validates a file-based policy configuration
func validateFileBasedConfig(config *FileBasedConfig) error {
	result := ValidateFileBasedConfig(config)
	if !result.IsValid() {
		// Return the first error for backward compatibility
		if len(result.Errors) > 0 {
			return result.Errors[0]
		}
		return fmt.Errorf("configuration validation failed")
	}
	return nil
}

// SaveFileBasedConfig saves a file-based policy configuration to a file
func SaveFileBasedConfig(config *FileBasedConfig, configPath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy config file: %w", err)
	}

	return nil
}
