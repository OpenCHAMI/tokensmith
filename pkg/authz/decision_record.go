// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import "context"

// DecisionRecord is a safe-to-log summary of an AuthZ decision.
//
// Contract:
//   - MUST NOT include raw JWT strings.
//   - MUST NOT include arbitrary claim values.
//   - SHOULD only include roles if they are considered non-sensitive in your deployment.
//
// DecisionRecord is intended to be emitted once per request in SHADOW and ENFORCE
// modes when the request is evaluated (i.e., not in OFF mode and not bypassed
// as public).
//
// It is provided to the OnDecision hook.
type DecisionRecord struct {
	PrincipalID   string   `json:"principal_id"`
	PrincipalType string   `json:"principal_type,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	RolesCount    int      `json:"roles_count"`

	Object string `json:"object"`
	Action string `json:"action"`
	Domain string `json:"domain,omitempty"`

	Decision      Decision `json:"decision"`
	Reason        Reason   `json:"reason"`
	Mode          Mode     `json:"mode"`
	PolicyVersion string   `json:"policy_version"`

	Method    string `json:"method"`
	Path      string `json:"path"`
	RequestID string `json:"request_id,omitempty"`
}

// OnDecisionHook is invoked with a DecisionRecord for observability.
//
// Implementations MUST be fast and MUST NOT block request handling.
// Callers should treat ctx as request-scoped and not retain it.
type OnDecisionHook func(ctx context.Context, rec DecisionRecord)
