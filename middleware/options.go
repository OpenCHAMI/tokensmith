package middleware

import "net/http"

// AuthzOptions contains configuration for the authorization middleware.
//
// Fields:
//   - ExemptPaths: list of request paths to skip authorization checks. Exact-match or prefix-match
//     is supported (paths ending with "*" will be treated as prefix matches).
//   - ContextKey: the context key (string) where JWT claims are stored by the JWT middleware.
//     Default is "jwt_claims" which corresponds to ClaimsContextKey in this package.
//   - FailOpen: when true, errors from the enforcer (e.g. internal adapter errors) will result
//     in allowing the request instead of failing closed. Default: false.
//   - SubjectMapper: optional function to map JWT claims and request to a list of Casbin subjects.
//     If nil, the default mapping will be used (priority: realm_access.roles -> roles claim ->
//     user:<sub>). The subject strings produced by the mapper should match the subjects used in
//     your Casbin policies (examples: "role:admin", "user:alice").
//   - ObjectMapper: optional function to derive the Casbin object string from the HTTP request
//     and claims. Defaults to the request path (r.URL.Path).
//   - ActionMapper: optional function to derive the Casbin action string from the HTTP request
//     and claims. Defaults to the HTTP method (lowercased).
//
// Note: The JWT verification middleware must run before AuthzMiddleware so that claims are
// populated in the request context.
type AuthzOptions struct {
	ExemptPaths   []string
	ContextKey    string
	FailOpen      bool
	SubjectMapper func(r *http.Request, claims interface{}) []string
	ObjectMapper  func(r *http.Request, claims interface{}) string
	ActionMapper  func(r *http.Request, claims interface{}) string
}
