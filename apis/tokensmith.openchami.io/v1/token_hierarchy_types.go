// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package v1

import (
	"time"

	"github.com/openchami/fabrica/pkg/resource"
)

// TokenHierarchy is a Fabrica resource for tracking parent-child token relationships.
//
// This resource enables:
// - Claim inheritance (children inherit AMR, ACR, auth_time from parents)
// - Cascade revocation (revoking parent revokes all descendants)
// - Audit trail (track token lineage and MFA provenance)
// - Scope restriction (children can subset parent scopes but never elevate)
//
// Storage Strategy:
// - Dedicated PostgreSQL table: token_hierarchies
// - O(1) child lookup via indexed ChildTokenID
// - O(n) parent lookup via indexed ParentTokenID (for cascade operations)
// - Immutable relationships (tokens cannot reparent)
//
// Security:
// - Immutable parent-child linkage prevents relationship manipulation
// - Claim validation prevents privilege escalation
// - Circular reference detection at creation time
//
// +fabrica:resource
// +fabrica:storage=dedicated
// +fabrica:storage:backend=postgres
// +fabrica:storage:table=token_hierarchies
// +fabrica:index:parent_token_id
// +fabrica:index:child_token_id
// +fabrica:index:created_at
type TokenHierarchy struct {
	APIVersion string               `json:"apiVersion"`
	Kind       string               `json:"kind"`
	Metadata   resource.Metadata    `json:"metadata"`
	Spec       TokenHierarchySpec   `json:"spec" validate:"required"`
	Status     TokenHierarchyStatus `json:"status,omitempty"`
}

// TokenHierarchySpec defines the immutable parent-child relationship.
type TokenHierarchySpec struct {
	// ParentTokenID is the JWT ID (jti) of the parent token.
	// +fabrica:field:immutable
	// +fabrica:field:index
	ParentTokenID string `json:"parent_token_id" validate:"required"`

	// ChildTokenID is the JWT ID (jti) of the child token.
	// +fabrica:field:immutable
	// +fabrica:field:unique
	// +fabrica:field:index
	ChildTokenID string `json:"child_token_id" validate:"required"`

	// Subject identifies the user/service (must match between parent and child).
	// +fabrica:field:immutable
	// +fabrica:field:index
	Subject string `json:"subject" validate:"required"`

	// InheritedClaims captures the claims inherited from parent at creation time.
	// +fabrica:field:immutable
	InheritedClaims InheritedClaims `json:"inherited_claims" validate:"required"`

	// CreatedAt is when this relationship was established.
	// +fabrica:field:immutable
	// +fabrica:field:index
	CreatedAt time.Time `json:"created_at" validate:"required"`

	// Depth is the hierarchy depth (0 = root, 1 = direct child, etc.).
	// +fabrica:field:immutable
	Depth int `json:"depth" validate:"gte=0"`
}

// InheritedClaims captures MFA claims inherited from parent token.
// These are stored for audit trail and validation purposes.
type InheritedClaims struct {
	// AMR (Authentication Methods References) inherited from parent.
	AMR []string `json:"amr,omitempty"`

	// ACR (Authentication Context Class Reference) inherited from parent.
	ACR string `json:"acr,omitempty"`

	// AuthTime is when the original authentication occurred (inherited from parent).
	AuthTime int64 `json:"auth_time,omitempty"`

	// SessionID is the session identifier (inherited from parent).
	SessionID string `json:"session_id,omitempty"`

	// ParentScopes are the scopes the parent had (child must be subset).
	ParentScopes []string `json:"parent_scopes,omitempty"`
}

// TokenHierarchyStatus tracks the lifecycle state of the relationship.
type TokenHierarchyStatus struct {
	// RevokedAt is when this relationship was invalidated (cascade revocation).
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RevokedReason indicates why revocation occurred.
	RevokedReason string `json:"revoked_reason,omitempty"`

	// ChildCount is the number of direct children (denormalized for performance).
	ChildCount int `json:"child_count"`
}

// GetAPIVersion returns the APIVersion of the resource
func (t *TokenHierarchy) GetAPIVersion() string {
	return t.APIVersion
}

// SetAPIVersion sets the APIVersion of the resource
func (t *TokenHierarchy) SetAPIVersion(version string) {
	t.APIVersion = version
}

// GetKind returns the Kind of the resource
func (t *TokenHierarchy) GetKind() string {
	return t.Kind
}

// SetKind sets the Kind of the resource
func (t *TokenHierarchy) SetKind(kind string) {
	t.Kind = kind
}

// GetMetadata returns the Metadata of the resource
func (t *TokenHierarchy) GetMetadata() resource.Metadata {
	return t.Metadata
}

// SetMetadata sets the Metadata of the resource
func (t *TokenHierarchy) SetMetadata(metadata resource.Metadata) {
	t.Metadata = metadata
}

// GetUID returns the UID from metadata
func (t *TokenHierarchy) GetUID() string {
	return t.Metadata.UID
}

// DeepCopy creates a deep copy of TokenHierarchy
func (t *TokenHierarchy) DeepCopy() *TokenHierarchy {
	if t == nil {
		return nil
	}
	out := new(TokenHierarchy)
	*out = *t

	out.Spec.InheritedClaims.AMR = make([]string, len(t.Spec.InheritedClaims.AMR))
	copy(out.Spec.InheritedClaims.AMR, t.Spec.InheritedClaims.AMR)

	out.Spec.InheritedClaims.ParentScopes = make([]string, len(t.Spec.InheritedClaims.ParentScopes))
	copy(out.Spec.InheritedClaims.ParentScopes, t.Spec.InheritedClaims.ParentScopes)

	if t.Status.RevokedAt != nil {
		revokedAt := *t.Status.RevokedAt
		out.Status.RevokedAt = &revokedAt
	}

	return out
}
