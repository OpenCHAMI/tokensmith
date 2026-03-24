// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import "net/http"

// RouteDecision is the service-owned mapping output that TokenSmith uses as
// Casbin input.
//
// Ownership contract:
//   - TokenSmith middleware owns *public bypass* decisions.
//   - RouteMapper MUST NOT attempt to enforce bypass; it only maps.
//   - RouteMapper MUST be pure/fast and MUST NOT perform I/O.
//
// Public is included for historical compatibility with early experiments, but
// is ignored by TokenSmith middleware.
//
// Mapped indicates whether TokenSmith should treat the request as having a
// known mapping to (Object, Action[, Domain]). In enforce mode, unmapped
// requests are denied-by-default unless explicitly configured otherwise.
//
// Object and Action are service-defined identifiers (or normalized path/method
// in path/method mode). They MUST NOT be derived from user-provided params.
//
// Domain is optional and may be empty if domains are unused.
//
// See docs/authz-spec.md for wire semantics.
type RouteDecision struct {
	Public bool
	Mapped bool
	Object string
	Action string
	Domain string
}

// RouteMapper maps an HTTP request + verified principal to a RouteDecision.
//
// Contract:
//   - Map MUST be deterministic and fast.
//   - Map MUST NOT perform I/O.
//   - Map MUST NOT mutate the request.
//   - Map MUST NOT decide public bypass; middleware is the single owner of that
//     behavior.
//
// Error contract:
//   - If Map returns a non-nil error, middleware MUST treat the request as a
//     deterministic denial with reason either:
//   - bad_request (HTTP 400) for errors that implement BadRequestError
//   - engine_error (HTTP 500) for all other errors
//
// Mapper implementations SHOULD use BadRequestError for malformed inputs that
// can be attributed to the request itself (e.g., invalid header used for domain
// selection).
//
// NOTE: callers should prefer returning (RouteDecision{Mapped:false}, nil) for
// unknown routes rather than an error.
//
// See also: BadRequestError.
type RouteMapper interface {
	Map(r *http.Request, p Principal) (RouteDecision, error)
}

// BadRequestError marks an error as being caused by a malformed request. AuthZ
// middleware will translate this to reason=bad_request and HTTP 400.
//
// Use cases:
//   - malformed URL escapes during path normalization
//   - invalid/missing required header used for domain routing
//
// The concrete error message SHOULD be stable and SHOULD NOT include sensitive
// values.
type BadRequestError interface {
	error
	BadRequest() bool
}

// badRequestError is a simple BadRequestError implementation.
type badRequestError struct{ msg string }

func (e badRequestError) Error() string    { return e.msg }
func (e badRequestError) BadRequest() bool { return true }

// NewBadRequestError returns an error that will be treated as bad_request.
func NewBadRequestError(msg string) error { return badRequestError{msg: msg} }
