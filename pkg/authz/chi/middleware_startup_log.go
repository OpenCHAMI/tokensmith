// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package chi

import (
	"log"
)

// LogStartupDiagnostics logs the effective authz mode and policy diagnostics.
//
// Services SHOULD call this once at startup.
func LogStartupDiagnostics(mode string, policyVersion string, source PolicySource) {
	log.Printf("authz mode=%s policy_version=%s policy_source=%s", mode, policyVersion, source)
}
