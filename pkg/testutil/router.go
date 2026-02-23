// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package testutil

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/openchami/tokensmith/pkg/authz"
	authzchi "github.com/openchami/tokensmith/pkg/authz/chi"
)

// AuthzTestRouter returns a chi.Router with TokenSmith AuthZ middleware
// installed.
//
// This does not install TokenSmith AuthN; callers should set principals via the
// authzchi.SetPrincipal helper within a small authn middleware in tests.
func AuthzTestRouter(a *authz.Authorizer, mode authz.Mode, opts ...authzchi.Option) chi.Router {
	mw := authzchi.New(a, append([]authzchi.Option{authzchi.WithMode(mode), authzchi.WithAllowMissingPrincipal(true)}, opts...)...)

	r := chi.NewRouter()
	r.Use(mw.Handler)
	return r
}

// PrincipalMiddleware is a tiny test AuthN shim that injects a principal from
// a provided callback.
func PrincipalMiddleware(f func(r *http.Request) *authz.Principal) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := f(r)
			if p != nil {
				r = r.WithContext(authzchi.SetPrincipal(r.Context(), p))
			}
			next.ServeHTTP(w, r)
		})
	}
}
