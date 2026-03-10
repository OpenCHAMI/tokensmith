// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package chi

import "github.com/openchami/tokensmith/pkg/authz"

// PromMetrics is a lightweight, pluggable metrics sink that exposes the stable
// TokenSmith AuthZ metrics label set.
//
// This implementation intentionally avoids taking a hard dependency on a
// specific metrics backend (Prometheus, OpenTelemetry, etc.). Services can
// bridge this into their metrics stack.
//
// Metrics:
//   - authz_decisions_total{decision,object,action,mode,policy_version}
//   - authz_errors_total{stage,mode,policy_version}
//
// Note: these methods are called on every request when AuthZ is installed.
// Implementations SHOULD be non-blocking.
//
// If you want a Prometheus implementation, implement Metrics in your service
// using prometheus.CounterVec and register the counters with your registry.
type PromMetrics struct{}

// NewPromMetrics returns a Metrics implementation with the stable label set.
//
// It is a no-op placeholder suitable for tests and for services that want to
// provide their own metric wiring.
func NewPromMetrics() *PromMetrics { return &PromMetrics{} }

func (m *PromMetrics) IncAuthzDecision(_ authz.Decision, _, _, _, _ string) {}
func (m *PromMetrics) IncAuthzError(_, _, _ string)                         {}
