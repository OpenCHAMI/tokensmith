package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestSimplifiedEngineInterface tests the simplified engine interface
func TestSimplifiedEngineInterface(t *testing.T) {
	// Test that both engines implement the simplified interface
	var engines []Engine

	// Create static engine
	staticConfig := &StaticEngineConfig{
		Name:        "test-static",
		Version:     "1.0.0",
		Scopes:      []string{"read", "write"},
		Audiences:   []string{"service1", "service2"},
		Permissions: []string{"read:data", "write:data"},
	}
	staticEngine, err := NewStaticEngine(staticConfig)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}
	engines = append(engines, staticEngine)

	// Test that both engines can be used through the interface
	ctx := context.Background()
	policyCtx := &PolicyContext{
		Username:    "testuser",
		Groups:      []string{"admin"},
		Claims:      map[string]interface{}{"email": "test@example.com"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	for i, engine := range engines {
		decision, err := engine.EvaluatePolicy(ctx, policyCtx)
		if err != nil {
			t.Errorf("Engine %d EvaluatePolicy failed: %v", i, err)
		}
		if decision == nil {
			t.Errorf("Engine %d returned nil decision", i)
		}
	}
}

// TestPolicyTestingFramework tests the new testing framework
func TestPolicyTestingFramework(t *testing.T) {
	// Create a static engine for testing
	config := &StaticEngineConfig{
		Name:          "test-engine",
		Version:       "1.0.0",
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"test_claim": "test_value",
		},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		t.Fatalf("Failed to create static engine: %v", err)
	}

	// Create test suite
	testSuite := NewPolicyTestSuite(engine, "test-engine")

	// Create test data factory
	factory := NewTestDataFactory()

	// Create expected decision that matches the engine configuration
	expectedDecision := &PolicyDecision{
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"test_claim": "test_value",
		},
	}

	// Create test cases
	testCases := []TestCase{
		factory.CreateTestCase(
			"basic_user",
			"Test basic user policy evaluation",
			factory.CreatePolicyContext("user1", []string{"users"}, map[string]interface{}{"email": "user1@example.com"}),
			expectedDecision,
			false,
		),
		factory.CreateTestCase(
			"admin_user",
			"Test admin user policy evaluation",
			factory.CreatePolicyContext("admin1", []string{"admins"}, map[string]interface{}{"email": "admin1@example.com"}),
			expectedDecision,
			false,
		),
	}

	// Run test suite
	ctx := context.Background()
	results := testSuite.RunTestSuite(ctx, testCases)

	// Check results
	for _, result := range results {
		if !result.Passed {
			t.Errorf("Test case '%s' failed: %s", result.TestCase.Name, result.Message)
		}
	}
}

// TestPolicyValidation tests the new validation system
func TestPolicyValidation(t *testing.T) {
	validator := DefaultValidator()

	// Test valid policy decision
	validDecision := &PolicyDecision{
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1", "service2"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"test_claim": "test_value",
		},
	}

	result := validator.ValidatePolicyDecision(validDecision)
	if !result.IsValid() {
		t.Errorf("Valid policy decision failed validation: %v", result.Errors)
	}

	// Test invalid policy decision
	invalidDecision := &PolicyDecision{
		Scopes:      []string{""}, // Empty scope
		Audiences:   []string{},   // Empty audiences
		Permissions: []string{},   // Empty permissions
	}

	result = validator.ValidatePolicyDecision(invalidDecision)
	if result.IsValid() {
		t.Error("Invalid policy decision passed validation")
	}

	// Test policy context validation
	validContext := &PolicyContext{
		Username:    "testuser",
		Groups:      []string{"users"},
		Claims:      map[string]interface{}{"email": "test@example.com"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	result = validator.ValidatePolicyContext(validContext)
	if !result.IsValid() {
		t.Errorf("Valid policy context failed validation: %v", result.Errors)
	}

	// Test invalid policy context
	invalidContext := &PolicyContext{
		Username:    "",           // Empty username
		Groups:      []string{""}, // Empty group
		Claims:      map[string]interface{}{},
		ClusterID:   "", // Empty cluster ID
		OpenCHAMIID: "", // Empty OpenCHAMI ID
	}

	result = validator.ValidatePolicyContext(invalidContext)
	if result.IsValid() {
		t.Error("Invalid policy context passed validation")
	}
}

// TestPolicyLogging tests the new logging system
func TestPolicyLogging(t *testing.T) {
	logger := NewPolicyLogger()
	ctx := context.Background()

	policyCtx := &PolicyContext{
		Username:    "testuser",
		Groups:      []string{"users"},
		Claims:      map[string]interface{}{"email": "test@example.com"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	decision := &PolicyDecision{
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"test_claim": "test_value",
		},
	}

	// Test successful policy decision logging
	logger.LogPolicyDecision(ctx, policyCtx, decision, "test-engine", time.Millisecond*100, nil)

	// Test error logging
	logger.LogPolicyError(ctx, policyCtx, "test-engine", fmt.Errorf("test error"))

	// Test configuration change logging
	logger.LogPolicyConfigChange("test-engine", "/path/to/config.json", nil)

	// Test validation logging
	logger.LogPolicyValidation("test-engine", true, nil)
}

// TestPolicyDocumentation tests the documentation generation
func TestPolicyDocumentation(t *testing.T) {
	generator := NewDocumentationGenerator()

	// Test static engine documentation
	staticConfig := &StaticEngineConfig{
		Name:          "test-static-engine",
		Version:       "1.0.0",
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1", "service2"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"test_claim": "test_value",
		},
	}

	doc, err := generator.GenerateStaticEngineDocs(staticConfig)
	if err != nil {
		t.Fatalf("Failed to generate static engine docs: %v", err)
	}

	if doc.Title == "" {
		t.Error("Documentation title is empty")
	}

	if len(doc.Sections) == 0 {
		t.Error("Documentation has no sections")
	}

	// Test markdown generation
	markdown, err := generator.GenerateMarkdown(doc.PolicyDocumentation)
	if err != nil {
		t.Fatalf("Failed to generate markdown: %v", err)
	}

	if markdown == "" {
		t.Error("Generated markdown is empty")
	}

	// Test file-based engine documentation
	fileBasedConfig := &FileBasedConfig{
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
		},
		UserRoleMappings: map[string][]string{
			"adminuser": {"admin"},
		},
		GroupRoleMappings: map[string][]string{
			"admins": {"admin"},
		},
	}

	doc, err = generator.GenerateFileBasedEngineDocs(fileBasedConfig)
	if err != nil {
		t.Fatalf("Failed to generate file-based engine docs: %v", err)
	}

	if doc.Title == "" {
		t.Error("File-based documentation title is empty")
	}

	if len(doc.Sections) == 0 {
		t.Error("File-based documentation has no sections")
	}
}

// TestPolicyDecisionSummary tests the policy decision summary
func TestPolicyDecisionSummary(t *testing.T) {
	policyCtx := &PolicyContext{
		Username:    "testuser",
		Groups:      []string{"users"},
		Claims:      map[string]interface{}{"email": "test@example.com"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	decision := &PolicyDecision{
		Scopes:        []string{"read", "write"},
		Audiences:     []string{"service1"},
		Permissions:   []string{"read:data", "write:data"},
		TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
		AdditionalClaims: map[string]interface{}{
			"test_claim": "test_value",
		},
	}

	summary := GetPolicyDecisionSummary("test-engine", policyCtx, decision, time.Millisecond*100, nil)

	if summary.Engine != "test-engine" {
		t.Errorf("Expected engine 'test-engine', got '%s'", summary.Engine)
	}

	if summary.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", summary.Username)
	}

	if len(summary.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(summary.Scopes))
	}

	// Test JSON serialization
	json, err := summary.ToJSON()
	if err != nil {
		t.Fatalf("Failed to serialize summary to JSON: %v", err)
	}

	if len(json) == 0 {
		t.Error("Serialized JSON is empty")
	}

	// Test string representation
	str := summary.String()
	if str == "" {
		t.Error("String representation is empty")
	}
}

// BenchmarkStaticEngine benchmarks the static policy engine
func BenchmarkStaticEngine(b *testing.B) {
	config := &StaticEngineConfig{
		Name:        "benchmark-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read", "write"},
		Audiences:   []string{"service1"},
		Permissions: []string{"read:data", "write:data"},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		b.Fatalf("Failed to create static engine: %v", err)
	}

	policyCtx := &PolicyContext{
		Username:    "testuser",
		Groups:      []string{"users"},
		Claims:      map[string]interface{}{"email": "test@example.com"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	BenchmarkPolicyEngine(b, engine, policyCtx)
}

// BenchmarkStaticEngineConcurrent benchmarks the static policy engine with concurrent access
func BenchmarkStaticEngineConcurrent(b *testing.B) {
	config := &StaticEngineConfig{
		Name:        "benchmark-engine",
		Version:     "1.0.0",
		Scopes:      []string{"read", "write"},
		Audiences:   []string{"service1"},
		Permissions: []string{"read:data", "write:data"},
	}

	engine, err := NewStaticEngine(config)
	if err != nil {
		b.Fatalf("Failed to create static engine: %v", err)
	}

	policyCtx := &PolicyContext{
		Username:    "testuser",
		Groups:      []string{"users"},
		Claims:      map[string]interface{}{"email": "test@example.com"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}

	BenchmarkPolicyEngineConcurrent(b, engine, policyCtx)
}
