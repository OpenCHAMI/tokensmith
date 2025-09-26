package tokenservice

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openchami/tokensmith/pkg/policy"
)

// FileConfig represents the configuration stored in a file
type FileConfig struct {
	GroupScopes map[string][]string `json:"groupScopes"`
}

// PolicyEngineType represents the type of policy engine
type PolicyEngineType string

const (
	PolicyEngineTypeStatic    PolicyEngineType = "static"
	PolicyEngineTypeFileBased PolicyEngineType = "file-based"
)

// PolicyEngineConfig holds the configuration for policy engines
type PolicyEngineConfig struct {
	Type PolicyEngineType `json:"type"`

	// Static engine configuration
	Static *policy.StaticEngineConfig `json:"static,omitempty"`

	// File-based engine configuration
	FileBased *policy.FileBasedEngineConfig `json:"file_based,omitempty"`
}

// DefaultFileConfig returns a default file configuration
func DefaultFileConfig() *FileConfig {
	return &FileConfig{
		GroupScopes: map[string][]string{
			"admin":    {"admin", "write", "read"},
			"operator": {"write", "read"},
			"viewer":   {"read"},
			"user":     {"read"},
		},
	}
}

// LoadFileConfig loads configuration from a file
func LoadFileConfig(configPath string) (*FileConfig, error) {
	if configPath == "" {
		return DefaultFileConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config FileConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// SaveFileConfig saves configuration to a file
func SaveFileConfig(config *FileConfig, configPath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// NewPolicyEngine creates a new policy engine based on the configuration
func NewPolicyEngine(config *PolicyEngineConfig) (policy.Engine, error) {
	if config == nil {
		// Return a default static engine if no config provided
		return policy.NewStaticEngine(nil)
	}

	switch config.Type {
	case PolicyEngineTypeStatic:
		return policy.NewStaticEngine(config.Static)
	case PolicyEngineTypeFileBased:
		return policy.NewFileBasedEngine(config.FileBased)
	default:
		return nil, fmt.Errorf("unsupported policy engine type: %s", config.Type)
	}
}

// DefaultPolicyEngineConfig returns a default policy engine configuration
func DefaultPolicyEngineConfig() *PolicyEngineConfig {
	return &PolicyEngineConfig{
		Type: PolicyEngineTypeStatic,
		Static: &policy.StaticEngineConfig{
			Name:          "default-static-engine",
			Version:       "1.0.0",
			Scopes:        []string{"read", "write"},
			Audiences:     []string{"smd", "bss", "cloud-init"},
			Permissions:   []string{"read:basic", "write:basic"},
			TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
			AdditionalClaims: map[string]interface{}{
				"policy_engine": "static",
				"version":       "1.0.0",
			},
		},
	}
}
