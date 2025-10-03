// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policy provides documentation generation utilities
package policy

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
	"time"
)

// PolicyDocumentation represents generated policy documentation
type PolicyDocumentation struct {
	Title       string
	Description string
	GeneratedAt time.Time
	Version     string
	Sections    []DocumentationSection
}

// DocumentationSection represents a section of the documentation
type DocumentationSection struct {
	Title   string
	Content string
	Type    string // "text", "json", "yaml", "table"
}

// PolicyConfigDocumentation represents documentation for a policy configuration
type PolicyConfigDocumentation struct {
	*PolicyDocumentation
	ConfigType string
	Config     interface{}
}

// DocumentationGenerator generates policy documentation
type DocumentationGenerator struct {
	templates map[string]*template.Template
}

// NewDocumentationGenerator creates a new documentation generator
func NewDocumentationGenerator() *DocumentationGenerator {
	dg := &DocumentationGenerator{
		templates: make(map[string]*template.Template),
	}
	dg.initTemplates()
	return dg
}

// initTemplates initializes the documentation templates
func (dg *DocumentationGenerator) initTemplates() {
	// Main documentation template
	mainTemplate := `# {{.Title}}

{{.Description}}

**Generated:** {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}  
**Version:** {{.Version}}

{{range .Sections}}
## {{.Title}}

{{.Content}}

{{end}}
`

	// Policy decision template
	decisionTemplate := `### Policy Decision

**Scopes:** {{range $i, $scope := .Scopes}}{{if $i}}, {{end}}{{$scope}}{{end}}  
**Audiences:** {{range $i, $audience := .Audiences}}{{if $i}}, {{end}}{{$audience}}{{end}}  
**Permissions:** {{range $i, $permission := .Permissions}}{{if $i}}, {{end}}{{$permission}}{{end}}  
{{if .TokenLifetime}}**Token Lifetime:** {{.TokenLifetime}}  
{{end}}{{if .AdditionalClaims}}**Additional Claims:** {{range $key, $value := .AdditionalClaims}}
- {{$key}}: {{$value}}{{end}}
{{end}}`

	// Role template
	roleTemplate := `### {{.Name}}

{{.Description}}

**Scopes:** {{range $i, $scope := .Scopes}}{{if $i}}, {{end}}{{$scope}}{{end}}  
**Audiences:** {{range $i, $audience := .Audiences}}{{if $i}}, {{end}}{{$audience}}{{end}}  
**Permissions:** {{range $i, $permission := .Permissions}}{{if $i}}, {{end}}{{$permission}}{{end}}  
{{if .TokenLifetime}}**Token Lifetime:** {{.TokenLifetime}}  
{{end}}{{if .AdditionalClaims}}**Additional Claims:** {{range $key, $value := .AdditionalClaims}}
- {{$key}}: {{$value}}{{end}}
{{end}}`

	// User mapping template
	userMappingTemplate := `### User Role Mappings

| Username | Roles |
|----------|-------|
{{range $user, $roles := .}}{{range $i, $role := $roles}}{{if eq $i 0}}| {{$user}} | {{$role}}{{else}} | | {{$role}}{{end}}
{{end}}{{end}}`

	// Group mapping template
	groupMappingTemplate := `### Group Role Mappings

| Group | Roles |
|-------|-------|
{{range $group, $roles := .}}{{range $i, $role := $roles}}{{if eq $i 0}}| {{$group}} | {{$role}}{{else}} | | {{$role}}{{end}}
{{end}}{{end}}`

	// Parse templates
	dg.templates["main"] = template.Must(template.New("main").Parse(mainTemplate))
	dg.templates["decision"] = template.Must(template.New("decision").Parse(decisionTemplate))
	dg.templates["role"] = template.Must(template.New("role").Parse(roleTemplate))
	dg.templates["user_mapping"] = template.Must(template.New("user_mapping").Parse(userMappingTemplate))
	dg.templates["group_mapping"] = template.Must(template.New("group_mapping").Parse(groupMappingTemplate))
}

// GenerateStaticEngineDocs generates documentation for a static engine configuration
func (dg *DocumentationGenerator) GenerateStaticEngineDocs(config *StaticEngineConfig) (*PolicyConfigDocumentation, error) {
	doc := &PolicyConfigDocumentation{
		PolicyDocumentation: &PolicyDocumentation{
			Title:       fmt.Sprintf("Static Policy Engine: %s", config.Name),
			Description: "This document describes the configuration and behavior of a static policy engine.",
			GeneratedAt: time.Now(),
			Version:     config.Version,
			Sections:    make([]DocumentationSection, 0),
		},
		ConfigType: "static",
		Config:     config,
	}

	// Add configuration section
	configSection := DocumentationSection{
		Title:   "Configuration",
		Content: dg.formatStaticConfig(config),
		Type:    "text",
	}
	doc.Sections = append(doc.Sections, configSection)

	// Add policy decision section
	decision := &PolicyDecision{
		Scopes:           config.Scopes,
		Audiences:        config.Audiences,
		Permissions:      config.Permissions,
		TokenLifetime:    config.TokenLifetime,
		AdditionalClaims: config.AdditionalClaims,
	}

	decisionContent, err := dg.renderTemplate("decision", decision)
	if err != nil {
		return nil, fmt.Errorf("failed to render decision template: %w", err)
	}

	decisionSection := DocumentationSection{
		Title:   "Policy Decision",
		Content: decisionContent,
		Type:    "text",
	}
	doc.Sections = append(doc.Sections, decisionSection)

	return doc, nil
}

// GenerateFileBasedEngineDocs generates documentation for a file-based engine configuration
func (dg *DocumentationGenerator) GenerateFileBasedEngineDocs(config *FileBasedConfig) (*PolicyConfigDocumentation, error) {
	doc := &PolicyConfigDocumentation{
		PolicyDocumentation: &PolicyDocumentation{
			Title:       "File-Based Policy Engine Configuration",
			Description: "This document describes the configuration and behavior of a file-based policy engine with role-based access control.",
			GeneratedAt: time.Now(),
			Version:     config.Version,
			Sections:    make([]DocumentationSection, 0),
		},
		ConfigType: "file-based",
		Config:     config,
	}

	// Add default policy section
	if config.DefaultPolicy != nil {
		decisionContent, err := dg.renderTemplate("decision", config.DefaultPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to render default policy template: %w", err)
		}

		defaultSection := DocumentationSection{
			Title:   "Default Policy",
			Content: decisionContent,
			Type:    "text",
		}
		doc.Sections = append(doc.Sections, defaultSection)
	}

	// Add roles section
	if len(config.Roles) > 0 {
		rolesContent := "The following roles are defined in this policy configuration:\n\n"

		for roleName, rolePolicy := range config.Roles {
			roleContent, err := dg.renderTemplate("role", rolePolicy)
			if err != nil {
				return nil, fmt.Errorf("failed to render role template for %s: %w", roleName, err)
			}
			rolesContent += roleContent + "\n"
		}

		rolesSection := DocumentationSection{
			Title:   "Roles",
			Content: rolesContent,
			Type:    "text",
		}
		doc.Sections = append(doc.Sections, rolesSection)
	}

	// Add user mappings section
	if len(config.UserRoleMappings) > 0 {
		userMappingContent, err := dg.renderTemplate("user_mapping", config.UserRoleMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to render user mapping template: %w", err)
		}

		userMappingSection := DocumentationSection{
			Title:   "User Role Mappings",
			Content: userMappingContent,
			Type:    "table",
		}
		doc.Sections = append(doc.Sections, userMappingSection)
	}

	// Add group mappings section
	if len(config.GroupRoleMappings) > 0 {
		groupMappingContent, err := dg.renderTemplate("group_mapping", config.GroupRoleMappings)
		if err != nil {
			return nil, fmt.Errorf("failed to render group mapping template: %w", err)
		}

		groupMappingSection := DocumentationSection{
			Title:   "Group Role Mappings",
			Content: groupMappingContent,
			Type:    "table",
		}
		doc.Sections = append(doc.Sections, groupMappingSection)
	}

	return doc, nil
}

// GenerateMarkdown generates markdown documentation
func (dg *DocumentationGenerator) GenerateMarkdown(doc *PolicyDocumentation) (string, error) {
	return dg.renderTemplate("main", doc)
}

// formatStaticConfig formats a static configuration for documentation
func (dg *DocumentationGenerator) formatStaticConfig(config *StaticEngineConfig) string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("**Name:** %s\n", config.Name))
	buf.WriteString(fmt.Sprintf("**Version:** %s\n", config.Version))
	buf.WriteString(fmt.Sprintf("**Scopes:** %s\n", strings.Join(config.Scopes, ", ")))
	buf.WriteString(fmt.Sprintf("**Audiences:** %s\n", strings.Join(config.Audiences, ", ")))
	buf.WriteString(fmt.Sprintf("**Permissions:** %s\n", strings.Join(config.Permissions, ", ")))

	if config.TokenLifetime != nil {
		buf.WriteString(fmt.Sprintf("**Token Lifetime:** %s\n", *config.TokenLifetime))
	}

	if len(config.AdditionalClaims) > 0 {
		buf.WriteString("**Additional Claims:**\n")
		for key, value := range config.AdditionalClaims {
			buf.WriteString(fmt.Sprintf("- %s: %v\n", key, value))
		}
	}

	return buf.String()
}

// renderTemplate renders a template with the given data
func (dg *DocumentationGenerator) renderTemplate(templateName string, data interface{}) (string, error) {
	tmpl, exists := dg.templates[templateName]
	if !exists {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// GenerateEngineSummary generates a summary of all available policy engines
func GenerateEngineSummary() string {
	return `# Policy Engine Summary

## Available Policy Engines

### Static Policy Engine
- **Type:** Static
- **Description:** Always returns the same hardcoded scopes, audiences, and permissions
- **Use Case:** Simple deployments where all users should receive the same permissions
- **Configuration:** Inline configuration with scopes, audiences, and permissions

### File-Based Policy Engine
- **Type:** Dynamic
- **Description:** Reads policy configuration from a file with role-based access control
- **Use Case:** Complex deployments with different user roles and permissions
- **Configuration:** JSON file with roles, user mappings, and group mappings

## Policy Decision Structure

All policy engines return a PolicyDecision containing:
- **Scopes:** OAuth 2.0 scopes granted to the user
- **Audiences:** Intended recipients of the token
- **Permissions:** Specific permissions granted to the user
- **TokenLifetime:** Duration for which the token should be valid (optional)
- **AdditionalClaims:** Custom claims to be included in the token (optional)

## Policy Context

Policy evaluation is based on a PolicyContext containing:
- **Username:** User identifier from the upstream OIDC provider
- **Groups:** User's group memberships
- **Claims:** Additional claims from the upstream token
- **ClusterID:** OpenCHAMI cluster identifier
- **OpenCHAMIID:** OpenCHAMI entity identifier

## Integration

Policy engines are integrated into the TokenSmith service and are called during token exchange to determine the appropriate scopes, audiences, and permissions for each user.
`
}
