// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import (
	"context"
	"net/http"
	"strings"
)

type ctxKeyRequestID struct{}

// ContextWithRequestID stores a request id string in ctx.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID{}, requestID)
}

// RequestIDFromContext returns a request id string from ctx, if present.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(ctxKeyRequestID{}).(string)
	v = strings.TrimSpace(v)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

// DefaultRequestIDFromContext returns a request id using a best-effort chain:
//  1. ctx value set via ContextWithRequestID
//  2. (optional) X-Request-Id request header, if r is available to the caller
//
// Note: because authz.Middleware currently only supports a ctx extractor,
// header-based extraction is typically implemented in the service and stored in
// context using ContextWithRequestID.
func DefaultRequestIDFromContext(ctx context.Context) string {
	if v, ok := RequestIDFromContext(ctx); ok {
		return v
	}
	return ""
}

// RequestIDFromHeader returns the request id from r using the provided header
// name (default: X-Request-Id).
func RequestIDFromHeader(r *http.Request, header string) string {
	if r == nil {
		return ""
	}
	h := strings.TrimSpace(header)
	if h == "" {
		h = "X-Request-Id"
	}
	return strings.TrimSpace(r.Header.Get(h))
}
