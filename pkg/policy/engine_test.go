package policy

import (
	"testing"
	"time"
)

func TestDefaultPolicyDecision(t *testing.T) {
	decision := DefaultPolicyDecision()

	if len(decision.Scopes) == 0 {
		t.Error("Default policy decision should have scopes")
	}

	if len(decision.Audiences) == 0 {
		t.Error("Default policy decision should have audiences")
	}

	if len(decision.Permissions) == 0 {
		t.Error("Default policy decision should have permissions")
	}

	expectedScopes := []string{"read"}
	if !equalStringSlices(decision.Scopes, expectedScopes) {
		t.Errorf("Expected scopes %v, got %v", expectedScopes, decision.Scopes)
	}

	expectedAudiences := []string{"smd", "bss", "cloud-init"}
	if !equalStringSlices(decision.Audiences, expectedAudiences) {
		t.Errorf("Expected audiences %v, got %v", expectedAudiences, decision.Audiences)
	}

	expectedPermissions := []string{"read:basic"}
	if !equalStringSlices(decision.Permissions, expectedPermissions) {
		t.Errorf("Expected permissions %v, got %v", expectedPermissions, decision.Permissions)
	}
}

func TestMergePolicyDecisions(t *testing.T) {
	tests := []struct {
		name      string
		decisions []*PolicyDecision
		expected  *PolicyDecision
	}{
		{
			name:      "empty decisions",
			decisions: []*PolicyDecision{},
			expected:  DefaultPolicyDecision(),
		},
		{
			name:      "nil decisions",
			decisions: []*PolicyDecision{nil, nil},
			expected:  DefaultPolicyDecision(),
		},
		{
			name: "single decision",
			decisions: []*PolicyDecision{
				{
					Scopes:      []string{"read", "write"},
					Audiences:   []string{"service1"},
					Permissions: []string{"read:data", "write:data"},
				},
			},
			expected: &PolicyDecision{
				Scopes:      []string{"read", "write"},
				Audiences:   []string{"service1"},
				Permissions: []string{"read:data", "write:data"},
			},
		},
		{
			name: "multiple decisions with duplicates",
			decisions: []*PolicyDecision{
				{
					Scopes:      []string{"read", "write"},
					Audiences:   []string{"service1"},
					Permissions: []string{"read:data"},
				},
				{
					Scopes:      []string{"write", "admin"},
					Audiences:   []string{"service2"},
					Permissions: []string{"write:data", "admin:all"},
				},
			},
			expected: &PolicyDecision{
				Scopes:      []string{"read", "write", "admin"},
				Audiences:   []string{"service1", "service2"},
				Permissions: []string{"read:data", "write:data", "admin:all"},
			},
		},
		{
			name: "decisions with token lifetime",
			decisions: []*PolicyDecision{
				{
					Scopes:        []string{"read"},
					Audiences:     []string{"service1"},
					Permissions:   []string{"read:data"},
					TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
				},
				{
					Scopes:      []string{"write"},
					Audiences:   []string{"service2"},
					Permissions: []string{"write:data"},
					// No token lifetime - should not override
				},
			},
			expected: &PolicyDecision{
				Scopes:        []string{"read", "write"},
				Audiences:     []string{"service1", "service2"},
				Permissions:   []string{"read:data", "write:data"},
				TokenLifetime: func() *time.Duration { d := time.Hour; return &d }(),
			},
		},
		{
			name: "decisions with additional claims",
			decisions: []*PolicyDecision{
				{
					Scopes:      []string{"read"},
					Audiences:   []string{"service1"},
					Permissions: []string{"read:data"},
					AdditionalClaims: map[string]interface{}{
						"claim1": "value1",
						"claim2": "value2",
					},
				},
				{
					Scopes:      []string{"write"},
					Audiences:   []string{"service2"},
					Permissions: []string{"write:data"},
					AdditionalClaims: map[string]interface{}{
						"claim2": "overridden",
						"claim3": "value3",
					},
				},
			},
			expected: &PolicyDecision{
				Scopes:      []string{"read", "write"},
				Audiences:   []string{"service1", "service2"},
				Permissions: []string{"read:data", "write:data"},
				AdditionalClaims: map[string]interface{}{
					"claim1": "value1",
					"claim2": "overridden", // Later decision takes precedence
					"claim3": "value3",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MergePolicyDecisions(tt.decisions...)

			if !equalStringSlices(result.Scopes, tt.expected.Scopes) {
				t.Errorf("Expected scopes %v, got %v", tt.expected.Scopes, result.Scopes)
			}

			if !equalStringSlices(result.Audiences, tt.expected.Audiences) {
				t.Errorf("Expected audiences %v, got %v", tt.expected.Audiences, result.Audiences)
			}

			if !equalStringSlices(result.Permissions, tt.expected.Permissions) {
				t.Errorf("Expected permissions %v, got %v", tt.expected.Permissions, result.Permissions)
			}

			if tt.expected.TokenLifetime != nil {
				if result.TokenLifetime == nil {
					t.Error("Expected token lifetime, got nil")
				} else if *result.TokenLifetime != *tt.expected.TokenLifetime {
					t.Errorf("Expected token lifetime %v, got %v", *tt.expected.TokenLifetime, *result.TokenLifetime)
				}
			}

			if len(tt.expected.AdditionalClaims) > 0 {
				if len(result.AdditionalClaims) != len(tt.expected.AdditionalClaims) {
					t.Errorf("Expected %d additional claims, got %d", len(tt.expected.AdditionalClaims), len(result.AdditionalClaims))
				}

				for k, v := range tt.expected.AdditionalClaims {
					if result.AdditionalClaims[k] != v {
						t.Errorf("Expected additional claim %s=%v, got %v", k, v, result.AdditionalClaims[k])
					}
				}
			}
		})
	}
}
