// Package policy provides configuration validation utilities
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
	Value   interface{}
}

func (ve *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s (value: %v)", ve.Field, ve.Message, ve.Value)
}

// ValidationResult represents the result of configuration validation
type ValidationResult struct {
	Valid    bool
	Errors   []*ValidationError
	Warnings []string
}

// IsValid returns true if the validation result is valid
func (vr *ValidationResult) IsValid() bool {
	return vr.Valid && len(vr.Errors) == 0
}

// AddError adds a validation error
func (vr *ValidationResult) AddError(field, message string, value interface{}) {
	vr.Valid = false
	vr.Errors = append(vr.Errors, &ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// AddWarning adds a validation warning
func (vr *ValidationResult) AddWarning(message string) {
	vr.Warnings = append(vr.Warnings, message)
}

// NewValidationResult creates a new validation result
func NewValidationResult() *ValidationResult {
	return &ValidationResult{
		Valid:    true,
		Errors:   make([]*ValidationError, 0),
		Warnings: make([]string, 0),
	}
}

// PolicyConfigValidator provides configuration validation for policy engines
type PolicyConfigValidator struct {
	// Custom validation rules
	ScopePatterns      []*regexp.Regexp
	AudiencePatterns   []*regexp.Regexp
	PermissionPatterns []*regexp.Regexp
}

// NewPolicyConfigValidator creates a new policy configuration validator
func NewPolicyConfigValidator() *PolicyConfigValidator {
	return &PolicyConfigValidator{
		ScopePatterns:      []*regexp.Regexp{},
		AudiencePatterns:   []*regexp.Regexp{},
		PermissionPatterns: []*regexp.Regexp{},
	}
}

// AddScopePattern adds a validation pattern for scopes
func (pcv *PolicyConfigValidator) AddScopePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid scope pattern: %w", err)
	}
	pcv.ScopePatterns = append(pcv.ScopePatterns, regex)
	return nil
}

// AddAudiencePattern adds a validation pattern for audiences
func (pcv *PolicyConfigValidator) AddAudiencePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid audience pattern: %w", err)
	}
	pcv.AudiencePatterns = append(pcv.AudiencePatterns, regex)
	return nil
}

// AddPermissionPattern adds a validation pattern for permissions
func (pcv *PolicyConfigValidator) AddPermissionPattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid permission pattern: %w", err)
	}
	pcv.PermissionPatterns = append(pcv.PermissionPatterns, regex)
	return nil
}

// ValidatePolicyDecision validates a policy decision
func (pcv *PolicyConfigValidator) ValidatePolicyDecision(decision *PolicyDecision) *ValidationResult {
	result := NewValidationResult()

	if decision == nil {
		result.AddError("decision", "policy decision cannot be nil", nil)
		return result
	}

	// Validate scopes
	if len(decision.Scopes) == 0 {
		result.AddError("scopes", "at least one scope must be specified", decision.Scopes)
	} else {
		for i, scope := range decision.Scopes {
			if err := pcv.validateScope(scope); err != nil {
				result.AddError(fmt.Sprintf("scopes[%d]", i), err.Error(), scope)
			}
		}
	}

	// Validate audiences
	if len(decision.Audiences) == 0 {
		result.AddError("audiences", "at least one audience must be specified", decision.Audiences)
	} else {
		for i, audience := range decision.Audiences {
			if err := pcv.validateAudience(audience); err != nil {
				result.AddError(fmt.Sprintf("audiences[%d]", i), err.Error(), audience)
			}
		}
	}

	// Validate permissions
	if len(decision.Permissions) == 0 {
		result.AddError("permissions", "at least one permission must be specified", decision.Permissions)
	} else {
		for i, permission := range decision.Permissions {
			if err := pcv.validatePermission(permission); err != nil {
				result.AddError(fmt.Sprintf("permissions[%d]", i), err.Error(), permission)
			}
		}
	}

	// Validate token lifetime
	if decision.TokenLifetime != nil && *decision.TokenLifetime <= 0 {
		result.AddError("token_lifetime", "token lifetime must be positive", *decision.TokenLifetime)
	}

	// Validate additional claims
	if decision.AdditionalClaims != nil {
		for key, value := range decision.AdditionalClaims {
			if key == "" {
				result.AddError("additional_claims", "claim key cannot be empty", key)
			}
			if value == nil {
				result.AddWarning(fmt.Sprintf("additional claim '%s' has nil value", key))
			}
		}
	}

	return result
}

// ValidatePolicyContext validates a policy context
func (pcv *PolicyConfigValidator) ValidatePolicyContext(context *PolicyContext) *ValidationResult {
	result := NewValidationResult()

	if context == nil {
		result.AddError("context", "policy context cannot be nil", nil)
		return result
	}

	// Validate username
	if context.Username == "" {
		result.AddError("username", "username cannot be empty", context.Username)
	} else if len(context.Username) > 255 {
		result.AddError("username", "username too long (max 255 characters)", context.Username)
	}

	// Validate groups
	if context.Groups != nil {
		for i, group := range context.Groups {
			if group == "" {
				result.AddError(fmt.Sprintf("groups[%d]", i), "group name cannot be empty", group)
			} else if len(group) > 255 {
				result.AddError(fmt.Sprintf("groups[%d]", i), "group name too long (max 255 characters)", group)
			}
		}
	}

	// Validate cluster ID
	if context.ClusterID == "" {
		result.AddError("cluster_id", "cluster ID cannot be empty", context.ClusterID)
	}

	// Validate OpenCHAMI ID
	if context.OpenCHAMIID == "" {
		result.AddError("openchami_id", "OpenCHAMI ID cannot be empty", context.OpenCHAMIID)
	}

	return result
}

// validateScope validates a single scope
func (pcv *PolicyConfigValidator) validateScope(scope string) error {
	if scope == "" {
		return fmt.Errorf("scope cannot be empty")
	}

	if len(scope) > 100 {
		return fmt.Errorf("scope too long (max 100 characters)")
	}

	// Check against patterns if any are defined
	if len(pcv.ScopePatterns) > 0 {
		matched := false
		for _, pattern := range pcv.ScopePatterns {
			if pattern.MatchString(scope) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("scope does not match any allowed patterns")
		}
	}

	// Basic format validation
	if strings.Contains(scope, " ") {
		return fmt.Errorf("scope cannot contain spaces")
	}

	return nil
}

// validateAudience validates a single audience
func (pcv *PolicyConfigValidator) validateAudience(audience string) error {
	if audience == "" {
		return fmt.Errorf("audience cannot be empty")
	}

	if len(audience) > 255 {
		return fmt.Errorf("audience too long (max 255 characters)")
	}

	// Check against patterns if any are defined
	if len(pcv.AudiencePatterns) > 0 {
		matched := false
		for _, pattern := range pcv.AudiencePatterns {
			if pattern.MatchString(audience) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("audience does not match any allowed patterns")
		}
	}

	return nil
}

// validatePermission validates a single permission
func (pcv *PolicyConfigValidator) validatePermission(permission string) error {
	if permission == "" {
		return fmt.Errorf("permission cannot be empty")
	}

	if len(permission) > 255 {
		return fmt.Errorf("permission too long (max 255 characters)")
	}

	// Check against patterns if any are defined
	if len(pcv.PermissionPatterns) > 0 {
		matched := false
		for _, pattern := range pcv.PermissionPatterns {
			if pattern.MatchString(permission) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("permission does not match any allowed patterns")
		}
	}

	// Basic format validation - permissions should follow resource:action format
	if !strings.Contains(permission, ":") {
		return fmt.Errorf("permission should follow 'resource:action' format")
	}

	return nil
}

// DefaultValidator creates a validator with default validation rules
func DefaultValidator() *PolicyConfigValidator {
	validator := NewPolicyConfigValidator()

	// Add default patterns
	validator.AddScopePattern(`^[a-z][a-z0-9_]*$`)                      // lowercase, alphanumeric, underscore
	validator.AddAudiencePattern(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)        // alphanumeric, dot, underscore, hyphen
	validator.AddPermissionPattern(`^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$`) // resource:action format

	return validator
}

// ValidateStaticEngineConfig validates a static engine configuration
func ValidateStaticEngineConfig(config *StaticEngineConfig) *ValidationResult {
	result := NewValidationResult()
	validator := DefaultValidator()

	if config == nil {
		result.AddError("config", "configuration cannot be nil", nil)
		return result
	}

	// Validate basic fields
	if config.Name == "" {
		result.AddError("name", "name cannot be empty", config.Name)
	}

	if config.Version == "" {
		result.AddError("version", "version cannot be empty", config.Version)
	}

	// Validate policy decision
	decision := &PolicyDecision{
		Scopes:           config.Scopes,
		Audiences:        config.Audiences,
		Permissions:      config.Permissions,
		TokenLifetime:    config.TokenLifetime,
		AdditionalClaims: config.AdditionalClaims,
	}

	decisionResult := validator.ValidatePolicyDecision(decision)
	if !decisionResult.IsValid() {
		for _, err := range decisionResult.Errors {
			result.AddError(err.Field, err.Message, err.Value)
		}
	}

	return result
}

// ValidateFileBasedConfig validates a file-based configuration
func ValidateFileBasedConfig(config *FileBasedConfig) *ValidationResult {
	result := NewValidationResult()
	validator := DefaultValidator()

	if config == nil {
		result.AddError("config", "configuration cannot be nil", nil)
		return result
	}

	// Validate version
	if config.Version == "" {
		result.AddError("version", "version cannot be empty", config.Version)
	}

	// Validate default policy
	if config.DefaultPolicy != nil {
		defaultResult := validator.ValidatePolicyDecision(config.DefaultPolicy)
		if !defaultResult.IsValid() {
			for _, err := range defaultResult.Errors {
				result.AddError("default_policy."+err.Field, err.Message, err.Value)
			}
		}
	}

	// Validate roles
	if config.Roles == nil {
		result.AddError("roles", "roles cannot be nil", config.Roles)
	} else {
		for roleName, rolePolicy := range config.Roles {
			if roleName == "" {
				result.AddError("roles", "role name cannot be empty", roleName)
				continue
			}

			if rolePolicy == nil {
				result.AddError(fmt.Sprintf("roles.%s", roleName), "role policy cannot be nil", rolePolicy)
				continue
			}

			// Validate role policy
			roleDecision := &PolicyDecision{
				Scopes:           rolePolicy.Scopes,
				Audiences:        rolePolicy.Audiences,
				Permissions:      rolePolicy.Permissions,
				TokenLifetime:    rolePolicy.TokenLifetime,
				AdditionalClaims: rolePolicy.AdditionalClaims,
			}

			roleResult := validator.ValidatePolicyDecision(roleDecision)
			if !roleResult.IsValid() {
				for _, err := range roleResult.Errors {
					result.AddError(fmt.Sprintf("roles.%s.%s", roleName, err.Field), err.Message, err.Value)
				}
			}
		}
	}

	// Validate user role mappings
	for username, roles := range config.UserRoleMappings {
		if username == "" {
			result.AddError("user_role_mappings", "username cannot be empty", username)
			continue
		}

		for i, role := range roles {
			if role == "" {
				result.AddError(fmt.Sprintf("user_role_mappings.%s[%d]", username, i), "role cannot be empty", role)
			} else if config.Roles != nil && config.Roles[role] == nil {
				result.AddError(fmt.Sprintf("user_role_mappings.%s[%d]", username, i), "role does not exist", role)
			}
		}
	}

	// Validate group role mappings
	for groupName, roles := range config.GroupRoleMappings {
		if groupName == "" {
			result.AddError("group_role_mappings", "group name cannot be empty", groupName)
			continue
		}

		for i, role := range roles {
			if role == "" {
				result.AddError(fmt.Sprintf("group_role_mappings.%s[%d]", groupName, i), "role cannot be empty", role)
			} else if config.Roles != nil && config.Roles[role] == nil {
				result.AddError(fmt.Sprintf("group_role_mappings.%s[%d]", groupName, i), "role does not exist", role)
			}
		}
	}

	return result
}
