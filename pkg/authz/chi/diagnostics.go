// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package chi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// PolicySource describes where the effective policy came from.
type PolicySource string

const (
	PolicySourceBaselineOnly      PolicySource = "baseline-only"
	PolicySourceBaselineFragments PolicySource = "baseline+fragments"
)

// Diagnostics is the stable diagnostic payload services may expose.
type Diagnostics struct {
	Mode          string       `json:"mode"`
	PolicyVersion string       `json:"policy_version"`
	PolicySource  PolicySource `json:"policy_source"`
}

// DiagnosticsHandler returns a handler that responds with the current authz mode
// and policy version.
func DiagnosticsHandler(mode string, policyVersion string, source PolicySource) http.Handler {
	resp := Diagnostics{Mode: mode, PolicyVersion: policyVersion, PolicySource: source}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// PolicyVersionHash is a helper for hashing arbitrary policy bytes into the
// hex-encoded sha256 used as policy_version.
//
// Services typically should use authz.Authorizer.PolicyVersion() instead.
func PolicyVersionHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
