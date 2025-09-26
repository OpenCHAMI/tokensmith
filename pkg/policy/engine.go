// Package policy provides pluggable policy engines for determining token scopes, audiences, and permissions.
// This package allows for flexible policy decisions based on user identity, groups, and other contextual information.
package policy

import (
	"context"
	"time"
)

// PolicyDecision represents the result of a policy evaluation, containing the scopes,
// audiences, and permissions that should be granted to a user.
type PolicyDecision struct {
	// Scopes are the OAuth 2.0 scopes granted to the user
	Scopes []string `json:"scopes"`

	// Audiences are the intended recipients of the token
	Audiences []string `json:"audiences"`

	// Permissions are specific permissions granted to the user
	// These can be used for fine-grained authorization decisions
	Permissions []string `json:"permissions"`

	// TokenLifetime is the duration for which the token should be valid
	// If not set, a default lifetime will be used
	TokenLifetime *time.Duration `json:"token_lifetime,omitempty"`

	// AdditionalClaims are custom claims to be included in the token
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`
}

// PolicyContext contains the simplified context information needed for policy evaluation
type PolicyContext struct {
	// User information from the upstream OIDC provider
	Username string   `json:"username"`
	Groups   []string `json:"groups"`

	// Claims from the upstream token
	Claims map[string]interface{} `json:"claims"`

	// Cluster and deployment information
	ClusterID   string `json:"cluster_id"`
	OpenCHAMIID string `json:"openchami_id"`
}

// Engine defines the simplified interface for pluggable policy engines.
// Policy engines are responsible for determining what scopes, audiences, and permissions
// should be granted to a user based on their identity and context.
type Engine interface {
	// EvaluatePolicy determines the policy decision for a given user context.
	// This method should be thread-safe and can be called concurrently.
	EvaluatePolicy(ctx context.Context, policyCtx *PolicyContext) (*PolicyDecision, error)
}

// DefaultPolicyDecision returns a default policy decision with basic scopes and audiences
func DefaultPolicyDecision() *PolicyDecision {
	return &PolicyDecision{
		Scopes:      []string{"read"},
		Audiences:   []string{"smd", "bss", "cloud-init"},
		Permissions: []string{"read:basic"},
	}
}

// MergePolicyDecisions merges multiple policy decisions into a single decision.
// Scopes, audiences, and permissions are combined and deduplicated.
// The first non-nil TokenLifetime is used.
// AdditionalClaims are merged with later decisions taking precedence.
func MergePolicyDecisions(decisions ...*PolicyDecision) *PolicyDecision {
	if len(decisions) == 0 {
		return DefaultPolicyDecision()
	}

	merged := &PolicyDecision{
		Scopes:           make([]string, 0),
		Audiences:        make([]string, 0),
		Permissions:      make([]string, 0),
		AdditionalClaims: make(map[string]interface{}),
	}

	scopeSet := make(map[string]bool)
	audienceSet := make(map[string]bool)
	permissionSet := make(map[string]bool)

	hasValidDecision := false

	for _, decision := range decisions {
		if decision == nil {
			continue
		}

		hasValidDecision = true

		// Merge scopes
		for _, scope := range decision.Scopes {
			if !scopeSet[scope] {
				scopeSet[scope] = true
				merged.Scopes = append(merged.Scopes, scope)
			}
		}

		// Merge audiences
		for _, audience := range decision.Audiences {
			if !audienceSet[audience] {
				audienceSet[audience] = true
				merged.Audiences = append(merged.Audiences, audience)
			}
		}

		// Merge permissions
		for _, permission := range decision.Permissions {
			if !permissionSet[permission] {
				permissionSet[permission] = true
				merged.Permissions = append(merged.Permissions, permission)
			}
		}

		// Use first non-nil token lifetime
		if merged.TokenLifetime == nil && decision.TokenLifetime != nil {
			merged.TokenLifetime = decision.TokenLifetime
		}

		// Merge additional claims (later decisions take precedence)
		for k, v := range decision.AdditionalClaims {
			merged.AdditionalClaims[k] = v
		}
	}

	// If no valid decisions were found, return default policy
	if !hasValidDecision {
		return DefaultPolicyDecision()
	}

	return merged
}
