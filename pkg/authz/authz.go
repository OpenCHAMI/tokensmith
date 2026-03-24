// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package authz provides a normative authorization contract and core types
// used by OpenCHAMI services integrating TokenSmith.
package authz

// Mode controls how authorization outcomes impact request handling.
//
// See docs/authz_contract.md.
type Mode string

const (
	ModeOff     Mode = "off"
	ModeShadow  Mode = "shadow"
	ModeEnforce Mode = "enforce"
)

// Decision is the outcome taxonomy returned by the core evaluator.
//
// See docs/authz_contract.md.
type Decision string

const (
	DecisionAllow         Decision = "allow"
	DecisionDeny          Decision = "deny"
	DecisionIndeterminate Decision = "indeterminate"
	DecisionError         Decision = "error"
)

// ErrorCode is a stable, machine-readable code used in AuthZ error responses.
//
// See docs/authz_contract.md.
type ErrorCode string

const (
	ErrorCodeAuthzDenied        ErrorCode = "AUTHZ_DENIED"
	ErrorCodeAuthzIndeterminate ErrorCode = "AUTHZ_INDETERMINATE"
	ErrorCodeAuthzError         ErrorCode = "AUTHZ_ERROR"
)

// ErrorResponse is the standard JSON error schema returned by TokenSmith AuthZ
// middleware when a request is denied in enforce mode.
//
// See docs/authz_contract.md.
type ErrorResponse struct {
	Code          ErrorCode `json:"code"`
	Message       string    `json:"message"`
	RequestID     string    `json:"request_id,omitempty"`
	PolicyVersion string    `json:"policy_version"`
	Decision      Decision  `json:"decision"`
}
