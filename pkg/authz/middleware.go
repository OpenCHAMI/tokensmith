// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package authz provides net/http-compatible middleware implementing the
// TokenSmith authorization wire contract.
package authz

import (
	"context"
	"net/http"
)

type ctxKeyPrincipal struct{}

// PrincipalFromContext returns the principal previously attached to ctx.
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal{}).(*Principal)
	if !ok || p == nil {
		return nil, false
	}
	return p, true
}

// SetPrincipal attaches a verified principal to ctx.
//
// AuthN middleware should call this after token validation.
func SetPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal{}, p)
}

// Middleware evaluates authorization decisions for incoming requests.
//
// It is net/http compatible and can be used with any router.
//
// Public bypass:
//
// This middleware does not implement router-specific per-route bypass.
// Use PublicPrefixes/PublicRegexps (or a router-specific helper) to skip authz.
//
// When the request is public, middleware will call next without evaluation even
// in enforce mode.
//
// Mapping:
//
// Services must supply a RouteMapper to convert requests into Casbin input.
// See PathMethodMapper for a Casbin-native path/method style.
//
// RequireAuthn:
//
// When enabled, the absence of a principal yields 401 even in shadow/enforce.
// AuthN middleware should run before this middleware.
//
// See docs/authz-spec.md for decision semantics.
type Middleware struct {
	Authorizer *Authorizer
	Mapper     RouteMapper

	Mode                 Mode
	RequireAuthn         bool
	AllowUnmapped        bool
	PublicPrefixes       []string
	PublicRegexps        []func(string) bool
	RequestIDFromContext func(context.Context) string

	DenyWriter DenyWriter
}

// MiddlewareOption configures authz Middleware.
type MiddlewareOption func(*Middleware)

func WithMode(mode Mode) MiddlewareOption { return func(m *Middleware) { m.Mode = mode } }
func WithRequireAuthn(req bool) MiddlewareOption {
	return func(m *Middleware) { m.RequireAuthn = req }
}
func WithAllowUnmapped(allow bool) MiddlewareOption {
	return func(m *Middleware) { m.AllowUnmapped = allow }
}
func WithPublicPrefixes(pfx []string) MiddlewareOption {
	return func(m *Middleware) { m.PublicPrefixes = append([]string(nil), pfx...) }
}
func WithPublicRegexps(rs ...func(string) bool) MiddlewareOption {
	return func(m *Middleware) { m.PublicRegexps = append([]func(string) bool(nil), rs...) }
}
func WithRequestIDFromContext(f func(context.Context) string) MiddlewareOption {
	return func(m *Middleware) { m.RequestIDFromContext = f }
}

// NewMiddleware constructs authz middleware.
func NewMiddleware(authorizer *Authorizer, mapper RouteMapper, opts ...MiddlewareOption) *Middleware {
	m := &Middleware{
		Authorizer:           authorizer,
		Mapper:               mapper,
		Mode:                 ModeEnforce,
		RequestIDFromContext: func(context.Context) string { return "" },
		DenyWriter:           DenyWriter{},
	}
	for _, o := range opts {
		o(m)
	}
	if m.RequestIDFromContext == nil {
		m.RequestIDFromContext = func(context.Context) string { return "" }
	}
	return m
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || m.Mode == ModeOff {
			next.ServeHTTP(w, r)
			return
		}

		if m.isPublic(r) {
			next.ServeHTTP(w, r)
			return
		}

		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			if m.RequireAuthn {
				m.deny(w, r, http.StatusUnauthorized, DenyResponseV1{
					Code:     DenyCodeAuthNRequired,
					Message:  "authentication required",
					Decision: DecisionDeny,
					Reason:   ReasonNoPrincipal,
					Mode:     string(m.Mode),
					Request:  RequestSummary{Method: r.Method, Path: r.URL.Path},
					RequestID: func() string {
						if m.RequestIDFromContext == nil {
							return ""
						}
						return m.RequestIDFromContext(r.Context())
					}(),
				})
				return
			}
			// In shadow/enforce, if authn isn't required we can continue mapping with
			// an empty principal.
			p = &Principal{}
		}

		if m.Mapper == nil {
			m.handleDecision(next, w, r, *p, RouteDecision{Mapped: false}, nil)
			return
		}

		rd, err := m.Mapper.Map(r, *p)
		m.handleDecision(next, w, r, *p, rd, err)
	})
}

func (m *Middleware) handleDecision(next http.Handler, w http.ResponseWriter, r *http.Request, p Principal, rd RouteDecision, mapErr error) {
	input := Input{Object: rd.Object, Action: rd.Action, Domain: rd.Domain}

	if mapErr != nil {
		status := http.StatusInternalServerError
		code := DenyCodeAuthzEngineErr
		reason := ReasonEngineError
		msg := "authorization mapping error"
		if _, ok := mapErr.(BadRequestError); ok {
			status = http.StatusBadRequest
			code = DenyCodeBadRequest
			reason = ReasonBadRequest
			msg = mapErr.Error()
		}
		m.deny(w, r, status, DenyResponseV1{
			Code:     code,
			Message:  msg,
			Decision: DecisionError,
			Reason:   reason,
			Mode:     string(m.Mode),
			Principal: PrincipalSummary{
				ID:    p.ID,
				Type:  "",
				Roles: append([]string(nil), p.Roles...),
			},
			Input:         input,
			PolicyVersion: m.policyVersion(),
			Request:       RequestSummary{Method: r.Method, Path: r.URL.Path},
			RequestID:     m.requestIDFrom(r.Context()),
			Details:       map[string]any{"error": "mapper"},
		})
		return
	}

	if !rd.Mapped {
		if m.Mode == ModeEnforce && !m.AllowUnmapped {
			m.deny(w, r, http.StatusForbidden, DenyResponseV1{
				Code:     DenyCodeAuthzUnmapped,
				Message:  "unmapped route",
				Decision: DecisionDeny,
				Reason:   ReasonUnmappedRoute,
				Mode:     string(m.Mode),
				Principal: PrincipalSummary{
					ID:    p.ID,
					Type:  "",
					Roles: append([]string(nil), p.Roles...),
				},
				Input:         input,
				PolicyVersion: m.policyVersion(),
				Request:       RequestSummary{Method: r.Method, Path: r.URL.Path},
				RequestID:     m.requestIDFrom(r.Context()),
			})
			return
		}
		// shadow always allows; enforce allows if AllowUnmapped.
		next.ServeHTTP(w, r)
		return
	}

	decision, _ := m.Authorizer.Authorize(r.Context(), p, rd.Object, rd.Action)
	if m.Mode == ModeShadow {
		next.ServeHTTP(w, r)
		return
	}

	if decision == DecisionAllow {
		next.ServeHTTP(w, r)
		return
	}

	if decision == DecisionError {
		m.deny(w, r, http.StatusInternalServerError, DenyResponseV1{
			Code:     DenyCodeAuthzEngineErr,
			Message:  "authorization engine error",
			Decision: decision,
			Reason:   ReasonEngineError,
			Mode:     string(m.Mode),
			Principal: PrincipalSummary{
				ID:    p.ID,
				Type:  "",
				Roles: append([]string(nil), p.Roles...),
			},
			Input:         input,
			PolicyVersion: m.policyVersion(),
			Request:       RequestSummary{Method: r.Method, Path: r.URL.Path},
			RequestID:     m.requestIDFrom(r.Context()),
		})
		return
	}

	m.deny(w, r, http.StatusForbidden, DenyResponseV1{
		Code:     DenyCodeAuthzDenied,
		Message:  "access denied",
		Decision: decision,
		Reason:   ReasonPolicyDenied,
		Mode:     string(m.Mode),
		Principal: PrincipalSummary{
			ID:    p.ID,
			Type:  "",
			Roles: append([]string(nil), p.Roles...),
		},
		Input:         input,
		PolicyVersion: m.policyVersion(),
		Request:       RequestSummary{Method: r.Method, Path: r.URL.Path},
		RequestID:     m.requestIDFrom(r.Context()),
	})
}

func (m *Middleware) deny(w http.ResponseWriter, r *http.Request, status int, resp DenyResponseV1) {
	_ = m.DenyWriter.Write(w, r, status, resp)
}

func (m *Middleware) policyVersion() string {
	if m == nil || m.Authorizer == nil {
		return ""
	}
	return m.Authorizer.PolicyVersion()
}

func (m *Middleware) requestIDFrom(ctx context.Context) string {
	if m == nil || m.RequestIDFromContext == nil {
		return ""
	}
	return m.RequestIDFromContext(ctx)
}

func (m *Middleware) isPublic(r *http.Request) bool {
	p := r.URL.Path
	for _, pre := range m.PublicPrefixes {
		if pre != "" && len(p) >= len(pre) && p[:len(pre)] == pre {
			return true
		}
	}
	for _, re := range m.PublicRegexps {
		if re != nil && re(p) {
			return true
		}
	}
	return false
}
