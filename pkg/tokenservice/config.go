package tokenservice

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FileConfig represents the configuration stored in a file
type FileConfig struct {
	GroupScopes map[string][]string `json:"groupScopes"`
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
