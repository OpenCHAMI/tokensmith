// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package chi provides chi-specific authorization middleware and route helpers
// implementing the TokenSmith AuthZ contract.
package chi

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/openchami/tokensmith/pkg/authz"
)

// requirement holds a route-level object/action requirement.
//
// This is intentionally unexported and only constructible via Require()
// to keep object/action constants set at registration time (not from request
// parameters).
type requirement struct {
	object string
	action string
}

type ctxKeyPrincipal struct{}
type ctxKeyRequirement struct{}
type ctxKeySkipAuthz struct{}

type Metrics interface {
	IncAuthzDecision(decision authz.Decision, object, action, mode, policyVersion string)
	IncAuthzError(stage, mode, policyVersion string)
}

type nopMetrics struct{}

func (nopMetrics) IncAuthzDecision(_ authz.Decision, _, _, _, _ string) {}
func (nopMetrics) IncAuthzError(_, _, _ string)                         {}

// PrincipalFromContext returns the principal previously set into ctx by
// SetPrincipal() or by service-specific AuthN middleware.
func PrincipalFromContext(ctx context.Context) (*authz.Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal{}).(*authz.Principal)
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}

// SetPrincipal attaches the verified principal to the request context.
//
// Services that do not use TokenSmith AuthN middleware MAY call this from their
// own AuthN layer (after JWT validation).
func SetPrincipal(ctx context.Context, p *authz.Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal{}, p)
}

// Require attaches a constant (object, action) authorization requirement to the
// request context.
//
// IMPORTANT: object and action MUST be service-defined constants at route
// registration time; do not derive them from request params.
func Require(object, action string) func(http.Handler) http.Handler {
	req := requirement{object: object, action: action}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxKeyRequirement{}, req)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Public marks a route as explicitly skipping authorization.
//
// This is used to opt-out of deny-by-default when AuthZ middleware is installed.
func Public() func(http.Handler) http.Handler { return SkipAuthz() }

// SkipAuthz marks a route as explicitly skipping authorization.
func SkipAuthz() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxKeySkipAuthz{}, true)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type Middleware struct {
	authz         *authz.Authorizer
	mode          authz.Mode
	metrics       Metrics
	requestIDFunc func(context.Context) string
	policySource  PolicySource
	// okMissingPrincipal allows services to make certain endpoints public with no AuthN
	// while still installing AuthZ middleware globally. If false, missing principal
	// results in 401 unless route is SkipAuthz.
	okMissingPrincipal bool

	// internal counters used for tests/visibility (not API).
	enforcedDenials atomic.Uint64
}

type Option func(*Middleware)

// WithPolicySource sets the policy source annotation for diagnostics.
func WithPolicySource(source PolicySource) Option {
	return func(m *Middleware) { m.policySource = source }
}

// WithMode sets the authorization mode.
func WithMode(mode authz.Mode) Option {
	return func(m *Middleware) { m.mode = mode }
}

// WithMetrics sets a metrics sink.
func WithMetrics(metrics Metrics) Option {
	return func(m *Middleware) {
		if metrics == nil {
			m.metrics = nopMetrics{}
			return
		}
		m.metrics = metrics
	}
}

// WithRequestIDFunc sets a function used to extract a request id string from the
// request context for inclusion in denial responses.
func WithRequestIDFunc(f func(context.Context) string) Option {
	return func(m *Middleware) { m.requestIDFunc = f }
}

// WithAllowMissingPrincipal configures behavior when a route requires authz but
// the principal is missing.
//
// If allow is true, missing principal will be treated as authz denial (403) in
// enforce mode.
//
// If allow is false (default), missing principal results in 401 (AuthN failure)
// when the route is not Public/SkipAuthz.
func WithAllowMissingPrincipal(allow bool) Option {
	return func(m *Middleware) { m.okMissingPrincipal = allow }
}

// New returns a chi-compatible authorization middleware enforcing the TokenSmith
// AuthZ contract.
//
// Wire contract:
//
// This middleware's deny response schema and HTTP semantics are frozen by
// docs/authz-spec.md ("TokenSmith AuthN/AuthZ Wire Contract Spec (Frozen)").
//
// Ordering contract:
//
//	request-id (optional) -> authn (JWT validation) -> authz
func New(authorizer *authz.Authorizer, opts ...Option) *Middleware {
	m := &Middleware{
		authz:         authorizer,
		mode:          authz.ModeEnforce,
		metrics:       nopMetrics{},
		requestIDFunc: func(context.Context) string { return "" },
		policySource:  PolicySourceBaselineOnly,
	}
	for _, o := range opts {
		o(m)
	}
	if m.metrics == nil {
		m.metrics = nopMetrics{}
	}
	if m.requestIDFunc == nil {
		m.requestIDFunc = func(context.Context) string { return "" }
	}
	return m
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.mode == authz.ModeOff {
			next.ServeHTTP(w, r)
			return
		}

		if skip, _ := r.Context().Value(ctxKeySkipAuthz{}).(bool); skip {
			next.ServeHTTP(w, r)
			return
		}

		req, ok := r.Context().Value(ctxKeyRequirement{}).(requirement)
		if !ok || req.object == "" || req.action == "" {
			// Deny-by-default when installed.
			m.metrics.IncAuthzDecision(authz.DecisionIndeterminate, "", "", string(m.mode), m.policyVersion())
			m.deny(w, r, authz.DecisionIndeterminate, "missing authz requirement")
			return
		}

		principal, ok := PrincipalFromContext(r.Context())
		if !ok {
			if !m.okMissingPrincipal {
				// Contract: AuthN must run before AuthZ.
				http.Error(w, "missing principal", http.StatusUnauthorized)
				return
			}
			m.metrics.IncAuthzDecision(authz.DecisionIndeterminate, req.object, req.action, string(m.mode), m.policyVersion())
			m.deny(w, r, authz.DecisionIndeterminate, "missing principal")
			return
		}

		decision, res := m.authz.Authorize(r.Context(), *principal, req.object, req.action)
		_ = res
		m.metrics.IncAuthzDecision(decision, req.object, req.action, string(m.mode), m.policyVersion())

		switch m.mode {
		case authz.ModeShadow:
			// Always allow but emit metrics.
			next.ServeHTTP(w, r)
			return
		case authz.ModeEnforce:
			if decision == authz.DecisionAllow {
				next.ServeHTTP(w, r)
				return
			}
			m.enforcedDenials.Add(1)
			m.deny(w, r, decision, "access denied")
			return
		default:
			// Unknown mode => safe default.
			m.metrics.IncAuthzError("mode", string(m.mode), m.policyVersion())
			m.deny(w, r, authz.DecisionError, "invalid authz mode")
			return
		}
	})
}

func (m *Middleware) policyVersion() string {
	if m == nil || m.authz == nil {
		return ""
	}
	return m.authz.PolicyVersion()
}

func (m *Middleware) deny(w http.ResponseWriter, r *http.Request, decision authz.Decision, msg string) {
	if m.mode != authz.ModeEnforce {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	policyVersion := m.policyVersion()

	_ = json.NewEncoder(w).Encode(authz.ErrorResponse{
		Code:          codeForDecision(decision),
		Message:       msg,
		RequestID:     m.requestIDFunc(r.Context()),
		PolicyVersion: policyVersion,
		Decision:      decision,
	})
}

func codeForDecision(d authz.Decision) authz.ErrorCode {
	switch d {
	case authz.DecisionDeny:
		return authz.ErrorCodeAuthzDenied
	case authz.DecisionIndeterminate:
		return authz.ErrorCodeAuthzIndeterminate
	case authz.DecisionError:
		return authz.ErrorCodeAuthzError
	default:
		return authz.ErrorCodeAuthzError
	}
}
