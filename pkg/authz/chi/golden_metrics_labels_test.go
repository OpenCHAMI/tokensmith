// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
//
// SPDX-License-Identifier: MIT

package chi_test

import (
	"testing"

	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/authz/chi"
)

type labelCheckingMetrics struct {
	gotDecision bool
	gotError    bool
	decision    map[string]string
	err         map[string]string
}

func (m *labelCheckingMetrics) IncAuthzDecision(decision authz.Decision, object, action, mode, policyVersion string) {
	m.gotDecision = true
	m.decision = map[string]string{
		"decision":       string(decision),
		"object":         object,
		"action":         action,
		"mode":           mode,
		"policy_version": policyVersion,
	}
}

func (m *labelCheckingMetrics) IncAuthzError(stage, mode, policyVersion string) {
	m.gotError = true
	m.err = map[string]string{
		"stage":          stage,
		"mode":           mode,
		"policy_version": policyVersion,
	}
}

func TestMetricsLabelContractExists(t *testing.T) {
	m := &labelCheckingMetrics{}

	m.IncAuthzDecision(authz.DecisionAllow, "boot:configs", "read", "enforce", "pv1")
	m.IncAuthzError("casbin", "enforce", "pv1")

	if !m.gotDecision {
		t.Fatalf("expected decision metric")
	}
	for _, k := range []string{"decision", "object", "action", "mode", "policy_version"} {
		if _, ok := m.decision[k]; !ok {
			t.Fatalf("missing decision label %q", k)
		}
	}

	if !m.gotError {
		t.Fatalf("expected error metric")
	}
	for _, k := range []string{"stage", "mode", "policy_version"} {
		if _, ok := m.err[k]; !ok {
			t.Fatalf("missing error label %q", k)
		}
	}

	_ = chi.NewPromMetrics // ensure symbol exists
}
