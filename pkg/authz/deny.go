// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import (
	"encoding/json"
	"net/http"
)

// PrincipalSummary is safe to log and safe to return to clients.
//
// Redaction rules (contract):
//   - MUST NOT include raw JWTs.
//   - MUST NOT include arbitrary claims.
//   - SHOULD only include role/group identifiers if they are considered non-sensitive
//     in your deployment.
//
// Note: PrincipalSummary is intentionally decoupled from JWT claim structs.
// Services can populate it from any identity system.
type PrincipalSummary struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"`
	Roles []string `json:"roles,omitempty"`
}

// Input is the normalized authorization tuple passed to the evaluator and
// returned in deny responses.
//
// Domain is always present in the type shape to keep the contract stable; it may
// be empty when domains are unused.
type Input struct {
	Object string `json:"object"`
	Action string `json:"action"`
	Domain string `json:"domain,omitempty"`
}

// Reason is the coarse reason category for a denial.
//
// See docs/authz-spec.md.
type Reason string

const (
	ReasonNoPrincipal   Reason = "no_principal"
	ReasonInvalidToken  Reason = "invalid_token"
	ReasonPolicyDenied  Reason = "policy_denied"
	ReasonUnmappedRoute Reason = "unmapped_route"
	ReasonEngineError   Reason = "engine_error"
	ReasonBadRequest    Reason = "bad_request"
)

// DenyCode is a stable, machine-readable denial code.
//
// See docs/authz-spec.md.
type DenyCode string

const (
	DenyCodeAuthNRequired  DenyCode = "AUTHN_REQUIRED"
	DenyCodeAuthNInvalid   DenyCode = "AUTHN_INVALID"
	DenyCodeAuthzDenied    DenyCode = "AUTHZ_DENIED"
	DenyCodeAuthzUnmapped  DenyCode = "AUTHZ_UNMAPPED"
	DenyCodeAuthzEngineErr DenyCode = "AUTHZ_ENGINE_ERROR"
	DenyCodeBadRequest     DenyCode = "BAD_REQUEST"
	DenySchemaVersionV1    string   = "authz.deny.v1"
	denyContentTypeJSON             = "application/json; charset=utf-8"
)

// DenyResponseV1 is the frozen deny response schema (authz.deny.v1).
//
// This struct is used by both AuthN and AuthZ layers.
type DenyResponseV1 struct {
	SchemaVersion string           `json:"schema_version"`
	Code          DenyCode         `json:"code"`
	Message       string           `json:"message"`
	Decision      Decision         `json:"decision"`
	Reason        Reason           `json:"reason"`
	Mode          string           `json:"mode"`
	Principal     PrincipalSummary `json:"principal"`
	Input         Input            `json:"input"`
	PolicyVersion string           `json:"policy_version"`
	Request       RequestSummary   `json:"request"`
	RequestID     string           `json:"request_id,omitempty"`
	Details       map[string]any   `json:"details,omitempty"`
}

type RequestSummary struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// DenyWriter writes a DenyResponseV1 as JSON.
//
// It is safe to use for both AuthN and AuthZ denial responses.
//
// Contract:
// - Sets Content-Type to application/json; charset=utf-8
// - For HEAD requests, writes headers/status but suppresses the body.
// - Must not log sensitive values (DenyWriter does not log).
// - Ensures policy_version and mode are present even if empty.
type DenyWriter struct{}

func (DenyWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp DenyResponseV1) error {
	resp.SchemaVersion = DenySchemaVersionV1
	if resp.PolicyVersion == "" {
		// Ensure stable presence; empty indicates unknown/not configured.
		resp.PolicyVersion = ""
	}
	if resp.Mode == "" {
		resp.Mode = ""
	}

	w.Header().Set("Content-Type", denyContentTypeJSON)
	w.WriteHeader(status)

	if r != nil && r.Method == http.MethodHead {
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(resp)
}
