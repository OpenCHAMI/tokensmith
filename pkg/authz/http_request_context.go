// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import (
	"context"
	"net/http"
)

type ctxKeyHTTPRequest struct{}

// ContextWithHTTPRequest stores an *http.Request in context for downstream
// helpers (e.g., observability hooks).
//
// This is intended for internal TokenSmith middleware wiring; services generally
// should not rely on this.
func ContextWithHTTPRequest(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, ctxKeyHTTPRequest{}, r)
}
