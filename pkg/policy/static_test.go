package policy

import (
	"context"
	"testing"
	"time"
)

func TestNewStaticEngine(t *testing.T) {
	tests := []struct {
		name    string
		config  *StaticEngineConfig
		wantErr bool
	}{
		{
			name:    "nil config uses default",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "default config",
			config:  DefaultStaticConfig(),
			wantErr: false,
		},
		{
			name: "valid custom config",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{"read", "write"},
				Audiences:   []string{"service1", "service2"},
				Permissions: []string{"read:data", "write:data"},
			},
			wantErr: false,
		},
		{
			name: "empty name",
			config: &StaticEngineConfig{
				Name:        "",
				Version:     "1.0.0",
				Scopes:      []string{"read"},
				Audiences:   []string{"service1"},
				Permissions: []string{"read:data"},
			},
			wantErr: true,
		},
		{
			name: "empty version",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "",
				Scopes:      []string{"read"},
				Audiences:   []string{"service1"},
				Permissions: []string{"read:data"},
			},
			wantErr: true,
		},
		{
			name: "empty scopes",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{},
				Audiences:   []string{"service1"},
				Permissions: []string{"read:data"},
			},
			wantErr: true,
		},
		{
			name: "empty audiences",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{"read"},
				Audiences:   []string{},
				Permissions: []string{"read:data"},
			},
			wantErr: true,
		},
		{
			name: "empty permissions",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{"read"},
				Audiences:   []string{"service1"},
				Permissions: []string{},
			},
			wantErr: true,
		},
		{
			name: "empty scope string",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{"read", ""},
				Audiences:   []string{"service1"},
				Permissions: []string{"read:data"},
			},
			wantErr: true,
		},
		{
			name: "empty audience string",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{"read"},
				Audiences:   []string{"service1", ""},
				Permissions: []string{"read:data"},
			},
			wantErr: true,
		},
		{
			name: "empty permission string",
			config: &StaticEngineConfig{
				Name:        "test-engine",
				Version:     "1.0.0",
				Scopes:      []string{"read"},
				Audiences:   []string{"service1"},
				Permissions: []string{"read:data", ""},
			},
			wantErr: true,
		},
		{
			name: "invalid token lifetime",
			config: &StaticEngineConfig{
				Name:          "test-engine",
				Version:       "1.0.0",
				Scopes:        []string{"read"},
				Audiences:     []string{"service1"},
				Permissions:   []string{"read:data"},
				TokenLifetime: func() *time.Duration { d := -time.Hour; return &d }(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewStaticEngine(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStaticEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && engine == nil {
				t.Error("NewStaticEngine() returned nil engine without error")
			}
		})
	}
}

func TestStaticEngine_EvaluatePolicy(t *testing.T) {
	config := &StaticEngineConfig{
		Name:          "test-engine",
		Version:       "1.0.0",
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1", "service2"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := 2 * time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"custom_claim": "custom_value",
		},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}

	ctx := context.Background()
	policyCtx := &PolicyContext{
		Username: "testuser",
		Groups:   []string{"admin", "user"},
		Claims: map[string]interface{}{
			"email": "test@example.com",
		},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	decision, err := engine.EvaluatePolicy(ctx, policyCtx)
	if err != nil {
		t.Fatalf("EvaluatePolicy() error = %v", err)
	}

	// Check that the decision matches the configuration
	expectedScopes := []string{"read", "write"}
	if !equalStringSlices(decision.Scopes, expectedScopes) {
		t.Errorf("Expected scopes %v, got %v", expectedScopes, decision.Scopes)
	}

	expectedAudiences := []string{"service1", "service2"}
	if !equalStringSlices(decision.Audiences, expectedAudiences) {
		t.Errorf("Expected audiences %v, got %v", expectedAudiences, decision.Audiences)
	}

	expectedPermissions := []string{"read:data", "write:data"}
	if !equalStringSlices(decision.Permissions, expectedPermissions) {
		t.Errorf("Expected permissions %v, got %v", expectedPermissions, decision.Permissions)
	}

	if decision.TokenLifetime == nil {
		t.Error("Expected token lifetime, got nil")
	} else if *decision.TokenLifetime != 2*time.Hour {
		t.Errorf("Expected token lifetime %v, got %v", 2*time.Hour, *decision.TokenLifetime)
	}

	if decision.AdditionalClaims == nil {
		t.Error("Expected additional claims, got nil")
	} else if decision.AdditionalClaims["custom_claim"] != "custom_value" {
		t.Errorf("Expected custom_claim=custom_value, got %v", decision.AdditionalClaims["custom_claim"])
	}
}

func TestStaticEngine_GetName(t *testing.T) {
	config := &StaticEngineConfig{
		Name:        "test-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read"},
		Audiences:   []string{"service1"},
		Permissions: []string{"read:data"},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}

	if engine.GetName() != "test-engine" {
		t.Errorf("Expected name 'test-engine', got '%s'", engine.GetName())
	}
}

func TestStaticEngine_GetVersion(t *testing.T) {
	config := &StaticEngineConfig{
		Name:        "test-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read"},
		Audiences:   []string{"service1"},
		Permissions: []string{"read:data"},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}

	if engine.GetVersion() != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", engine.GetVersion())
	}
}

func TestStaticEngine_ValidateConfiguration(t *testing.T) {
	config := &StaticEngineConfig{
		Name:        "test-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read"},
		Audiences:   []string{"service1"},
		Permissions: []string{"read:data"},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}

	if err := engine.ValidateConfiguration(); err != nil {
		t.Errorf("ValidateConfiguration() error = %v", err)
	}
}

func TestStaticEngine_ThreadSafety(t *testing.T) {
	config := &StaticEngineConfig{
		Name:        "test-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read"},
		Audiences:   []string{"service1"},
		Permissions: []string{"read:data"},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}

	ctx := context.Background()
	policyCtx := &PolicyContext{
		Username: "testuser",
		Groups:   []string{"admin"},
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

func TestDefaultStaticConfig(t *testing.T) {
	config := DefaultStaticConfig()

	if config.Name == "" {
		t.Error("Default config should have a name")
	}

	if config.Version == "" {
		t.Error("Default config should have a version")
	}

	if len(config.Scopes) == 0 {
		t.Error("Default config should have scopes")
	}

	if len(config.Audiences) == 0 {
		t.Error("Default config should have audiences")
	}

	if len(config.Permissions) == 0 {
		t.Error("Default config should have permissions")
	}

	if config.TokenLifetime == nil {
		t.Error("Default config should have token lifetime")
	}

	if config.AdditionalClaims == nil {
		t.Error("Default config should have additional claims")
	}
}
