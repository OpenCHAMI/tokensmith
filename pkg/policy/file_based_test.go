package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewFileBasedEngine(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "policy.json")

	config := &FileBasedConfig{
		Version: "1.0.0",
		DefaultPolicy: &PolicyDecision{
			Scopes:      []string{"read"},
			Audiences:   []string{"default-service"},
			Permissions: []string{"read:basic"},
		},
		Roles: map[string]*RolePolicy{
			"admin": {
				Name:        "Administrator",
				Description: "Full administrative access",
				Scopes:      []string{"read", "write", "admin"},
				Audiences:   []string{"admin-service"},
				Permissions: []string{"read:all", "write:all", "admin:all"},
			},
			"user": {
				Name:        "Regular User",
				Description: "Basic user access",
				Scopes:      []string{"read"},
				Audiences:   []string{"user-service"},
				Permissions: []string{"read:basic"},
			},
		},
		UserRoleMappings: map[string][]string{
			"adminuser":   {"admin"},
			"regularuser": {"user"},
		},
		GroupRoleMappings: map[string][]string{
			"admins": {"admin"},
			"users":  {"user"},
		},
	}

	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	tests := []struct {
		name    string
		config  *FileBasedEngineConfig
		wantErr bool
	}{
		{
			name:    "nil config uses default",
			config:  nil,
			wantErr: true, // Default config path doesn't exist
		},
		{
			name: "valid config",
			config: &FileBasedEngineConfig{
				Name:       "test-engine",
				Version:    "1.0.0",
				ConfigPath: configPath,
			},
			wantErr: false,
		},
		{
			name: "empty name",
			config: &FileBasedEngineConfig{
				Name:       "",
				Version:    "1.0.0",
				ConfigPath: configPath,
			},
			wantErr: true,
		},
		{
			name: "empty version",
			config: &FileBasedEngineConfig{
				Name:       "test-engine",
				Version:    "",
				ConfigPath: configPath,
			},
			wantErr: true,
		},
		{
			name: "empty config path",
			config: &FileBasedEngineConfig{
				Name:       "test-engine",
				Version:    "1.0.0",
				ConfigPath: "",
			},
			wantErr: true,
		},
		{
			name: "non-existent config file",
			config: &FileBasedEngineConfig{
				Name:       "test-engine",
				Version:    "1.0.0",
				ConfigPath: "/non/existent/path.json",
			},
			wantErr: true,
		},
		{
			name: "invalid reload interval",
			config: &FileBasedEngineConfig{
				Name:           "test-engine",
				Version:        "1.0.0",
				ConfigPath:     configPath,
				ReloadInterval: func() *time.Duration { d := -time.Minute; return &d }(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewFileBasedEngine(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFileBasedEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && engine == nil {
				t.Error("NewFileBasedEngine() returned nil engine without error")
			}
		})
	}
}

func TestFileBasedEngine_EvaluatePolicy(t *testing.T) {
	// Create a temporary config file
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "policy.json")

	config := &FileBasedConfig{
		Version: "1.0.0",
		DefaultPolicy: &PolicyDecision{
			Scopes:      []string{"read"},
			Audiences:   []string{"default-service"},
			Permissions: []string{"read:basic"},
		},
		Roles: map[string]*RolePolicy{
			"admin": {
				Name:        "Administrator",
				Description: "Full administrative access",
				Scopes:      []string{"read", "write", "admin"},
				Audiences:   []string{"admin-service"},
				Permissions: []string{"read:all", "write:all", "admin:all"},
			},
			"user": {
				Name:        "Regular User",
				Description: "Basic user access",
				Scopes:      []string{"read"},
				Audiences:   []string{"user-service"},
				Permissions: []string{"read:basic"},
			},
		},
		UserRoleMappings: map[string][]string{
			"adminuser":   {"admin"},
			"regularuser": {"user"},
		},
		GroupRoleMappings: map[string][]string{
			"admins": {"admin"},
			"users":  {"user"},
		},
	}

	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	engineConfig := &FileBasedEngineConfig{
		Name:       "test-engine",
		Version:    "1.0.0",
		ConfigPath: configPath,
	}

	engine, err := NewFileBasedEngine(engineConfig)
	if err != nil {
		t.Fatalf("Failed to create file-based engine: %v", err)
	}

	tests := []struct {
		name                string
		policyCtx           *PolicyContext
		expectedScopes      []string
		expectedAudiences   []string
		expectedPermissions []string
	}{
		{
			name: "user with admin role",
			policyCtx: &PolicyContext{
				Username: "adminuser",
				Groups:   []string{},
				Claims:   map[string]interface{}{},
			},
			expectedScopes:      []string{"read", "write", "admin"},
			expectedAudiences:   []string{"admin-service"},
			expectedPermissions: []string{"read:all", "write:all", "admin:all"},
		},
		{
			name: "user with regular role",
			policyCtx: &PolicyContext{
				Username: "regularuser",
				Groups:   []string{},
				Claims:   map[string]interface{}{},
			},
			expectedScopes:      []string{"read"},
			expectedAudiences:   []string{"user-service"},
			expectedPermissions: []string{"read:basic"},
		},
		{
			name: "user with group-based admin role",
			policyCtx: &PolicyContext{
				Username: "someuser",
				Groups:   []string{"admins"},
				Claims:   map[string]interface{}{},
			},
			expectedScopes:      []string{"read", "write", "admin"},
			expectedAudiences:   []string{"admin-service"},
			expectedPermissions: []string{"read:all", "write:all", "admin:all"},
		},
		{
			name: "user with group-based user role",
			policyCtx: &PolicyContext{
				Username: "someuser",
				Groups:   []string{"users"},
				Claims:   map[string]interface{}{},
			},
			expectedScopes:      []string{"read"},
			expectedAudiences:   []string{"user-service"},
			expectedPermissions: []string{"read:basic"},
		},
		{
			name: "user with multiple roles",
			policyCtx: &PolicyContext{
				Username: "someuser",
				Groups:   []string{"admins", "users"},
				Claims:   map[string]interface{}{},
			},
			expectedScopes:      []string{"read", "write", "admin"},
			expectedAudiences:   []string{"admin-service", "user-service"},
			expectedPermissions: []string{"read:all", "write:all", "admin:all", "read:basic"},
		},
		{
			name: "user with no roles uses default",
			policyCtx: &PolicyContext{
				Username: "unknownuser",
				Groups:   []string{"unknown-group"},
				Claims:   map[string]interface{}{},
			},
			expectedScopes:      []string{"read"},
			expectedAudiences:   []string{"default-service"},
			expectedPermissions: []string{"read:basic"},
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := engine.EvaluatePolicy(ctx, tt.policyCtx)
			if err != nil {
				t.Fatalf("EvaluatePolicy() error = %v", err)
			}

			if !equalStringSlices(decision.Scopes, tt.expectedScopes) {
				t.Errorf("Expected scopes %v, got %v", tt.expectedScopes, decision.Scopes)
			}

			if !equalStringSlices(decision.Audiences, tt.expectedAudiences) {
				t.Errorf("Expected audiences %v, got %v", tt.expectedAudiences, decision.Audiences)
			}

			if !equalStringSlices(decision.Permissions, tt.expectedPermissions) {
				t.Errorf("Expected permissions %v, got %v", tt.expectedPermissions, decision.Permissions)
			}
		})
	}
}

func TestFileBasedEngine_GetName(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "policy.json")

	// Create minimal valid config
	config := &FileBasedConfig{
		Version: "1.0.0",
		Roles: map[string]*RolePolicy{
			"user": {
				Name:        "User",
				Scopes:      []string{"read"},
				Audiences:   []string{"service"},
				Permissions: []string{"read:basic"},
			},
		},
	}

	configData, _ := json.Marshal(config)
	os.WriteFile(configPath, configData, 0644)

	engineConfig := &FileBasedEngineConfig{
		Name:       "test-engine",
		Version:    "1.0.0",
		ConfigPath: configPath,
	}

	engine, err := NewFileBasedEngine(engineConfig)
	if err != nil {
		t.Fatalf("Failed to create file-based engine: %v", err)
	}

	if engine.GetName() != "test-engine" {
		t.Errorf("Expected name 'test-engine', got '%s'", engine.GetName())
	}
}

func TestFileBasedEngine_GetVersion(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "policy.json")

	// Create minimal valid config
	config := &FileBasedConfig{
		Version: "1.0.0",
		Roles: map[string]*RolePolicy{
			"user": {
				Name:        "User",
				Scopes:      []string{"read"},
				Audiences:   []string{"service"},
				Permissions: []string{"read:basic"},
			},
		},
	}

	configData, _ := json.Marshal(config)
	os.WriteFile(configPath, configData, 0644)

	engineConfig := &FileBasedEngineConfig{
		Name:       "test-engine",
		Version:    "1.0.0",
		ConfigPath: configPath,
	}

	engine, err := NewFileBasedEngine(engineConfig)
	if err != nil {
		t.Fatalf("Failed to create file-based engine: %v", err)
	}

	if engine.GetVersion() != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", engine.GetVersion())
	}
}

func TestFileBasedEngine_ValidateConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "policy.json")

	// Create minimal valid config
	config := &FileBasedConfig{
		Version: "1.0.0",
		Roles: map[string]*RolePolicy{
			"user": {
				Name:        "User",
				Scopes:      []string{"read"},
				Audiences:   []string{"service"},
				Permissions: []string{"read:basic"},
			},
		},
	}

	configData, _ := json.Marshal(config)
	os.WriteFile(configPath, configData, 0644)

	engineConfig := &FileBasedEngineConfig{
		Name:       "test-engine",
		Version:    "1.0.0",
		ConfigPath: configPath,
	}

	engine, err := NewFileBasedEngine(engineConfig)
	if err != nil {
		t.Fatalf("Failed to create file-based engine: %v", err)
	}

	if err := engine.ValidateConfiguration(); err != nil {
		t.Errorf("ValidateConfiguration() error = %v", err)
	}
}

func TestFileBasedEngine_ThreadSafety(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "policy.json")

	config := &FileBasedConfig{
		Version: "1.0.0",
		Roles: map[string]*RolePolicy{
			"user": {
				Name:        "User",
				Scopes:      []string{"read"},
				Audiences:   []string{"service"},
				Permissions: []string{"read:basic"},
			},
		},
		UserRoleMappings: map[string][]string{
			"testuser": {"user"},
		},
	}

	configData, _ := json.Marshal(config)
	os.WriteFile(configPath, configData, 0644)

	engineConfig := &FileBasedEngineConfig{
		Name:       "test-engine",
		Version:    "1.0.0",
		ConfigPath: configPath,
	}

	engine, err := NewFileBasedEngine(engineConfig)
	if err != nil {
		t.Fatalf("Failed to create file-based engine: %v", err)
	}

	ctx := context.Background()
	policyCtx := &PolicyContext{
		Username: "testuser",
		Groups:   []string{},
		Claims:   map[string]interface{}{},
	}

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			_, err := engine.EvaluatePolicy(ctx, policyCtx)
			if err != nil {
				t.Errorf("EvaluatePolicy() error = %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestDefaultFileBasedConfig(t *testing.T) {
	config := DefaultFileBasedConfig()

	if config.Name == "" {
		t.Error("Default config should have a name")
	}

	if config.Version == "" {
		t.Error("Default config should have a version")
	}

	if config.ConfigPath == "" {
		t.Error("Default config should have a config path")
	}

	if config.ReloadInterval == nil {
		t.Error("Default config should have a reload interval")
	}
}
