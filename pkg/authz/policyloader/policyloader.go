// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policyloader loads the TokenSmith baseline Casbin model+policy and
// optional filesystem policy fragments.
package policyloader

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/casbin/casbin/v2"
)

const (
	// EnvPolicyDir is the preferred env var pointing to a directory containing
	// Casbin policy fragment CSV files.
	EnvPolicyDir = "TOKENS_MITH_POLICY_DIR"

	// EnvPolicyDirCompat is an alternate env var name used by some deployments.
	EnvPolicyDirCompat = "AUTHZ_POLICY_DIR"
)

//go:embed baseline_model.conf
var baselineModelText string

//go:embed baseline_policy.csv
var baselinePolicyText string

// LoadFromEnv loads baseline model+policy plus optional policy fragments from
// the directory specified by TOKENS_MITH_POLICY_DIR or AUTHZ_POLICY_DIR.
//
// Grouping policy is not loaded by this legacy helper.
func (l *Loader) LoadFromEnv() (*casbin.Enforcer, error) {
	dir := strings.TrimSpace(os.Getenv(EnvPolicyDir))
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv(EnvPolicyDirCompat))
	}
	return l.Load(dir)
}

// Load loads the embedded baseline model+policy and optional policy fragments
// from policyDir.
//
// This is a legacy convenience API kept for backward compatibility.
// For new code, prefer (*Loader).Load(Source).
//
// Grouping policy is not loaded by this legacy helper.
func (l *Loader) Load(policyDir string) (*casbin.Enforcer, error) {
	// Legacy behavior: baseline model + baseline policy, plus optional policy
	// fragments from policyDir.
	src := Source{ModelText: baselineModelText}
	e, err := l.LoadSource(src)
	if err != nil {
		return nil, fmt.Errorf("load embedded baseline: %w", err)
	}

	// If a policyDir is provided, load additional *policy* fragments (not
	// grouping) and add them onto the enforcer.
	if strings.TrimSpace(policyDir) != "" {
		policyBytes, origins, err := readMaybeDirCSV(strings.TrimSpace(policyDir))
		if err != nil {
			return nil, err
		}
		lines, err := parsePolicyLines(bytes.NewReader(policyBytes), origins)
		if err != nil {
			return nil, err
		}
		if err := addPolicies(e, lines); err != nil {
			return nil, err
		}

		// Update policy version to include the additional fragments.
		pv := policyHash(baselineModelText, append([]byte(nil), baselinePolicyText...), policyBytes)
		l.mu.Lock()
		l.policyVersion = pv
		l.mu.Unlock()
	}
	if err != nil {
		return nil, fmt.Errorf("load baseline+policy fragments: %w", err)
	}
	return e, nil
}
