// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package deviceauth

import (
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/oidc"
)

// VerifyPrincipal applies the complete device-authorization token contract before
// mapping the verified subject and role into the existing authorization principal.
// lookup must use keys trusted for c.ClusterIssuer, never token-selected URLs.
// The caller must bound clock error and key-cache lifetime as required by Verify.
func VerifyPrincipal(raw string, c Config, now time.Time, lookup func(string) (*rsa.PublicKey, error)) (authz.Principal, error) {
	if lookup == nil {
		return authz.Principal{}, ErrDenied
	}
	claims, err := Verify(raw, c, now, func(kid string) (*rsa.PublicKey, error) {
		key, err := lookup(kid)
		if err != nil || key == nil {
			return nil, ErrDenied
		}
		return key, nil
	})
	if err != nil {
		return authz.Principal{}, ErrDenied
	}
	return authz.Principal{ID: claims.Subject, Roles: []string{claims.Role}}, nil
}

// Middleware authenticates Bearer credentials with VerifyPrincipal and attaches
// the principal using authz.SetPrincipal. Install it before authz.NewMiddleware
// on protected service routes; it does not choose policy or authorize actions.
// This uses the generic net/http authz context, not authz/chi's separate context.
// lookup and the host clock must satisfy Verify's trust and freshness contract.
func Middleware(c Config, lookup func(string) (*rsa.PublicKey, error)) (func(http.Handler) http.Handler, error) {
	if c.Validate() != nil || lookup == nil {
		return nil, ErrDenied
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := oidc.ParseBearerToken(r.Header.Get("Authorization"))
			var principal authz.Principal
			var err error
			if ok && len(r.Header.Values("Authorization")) == 1 {
				principal, err = VerifyPrincipal(raw, c, time.Now(), lookup)
			} else {
				err = ErrDenied
			}
			if err != nil {
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, ErrDenied.Error(), http.StatusUnauthorized)
				return
			}
			ctx := authz.SetPrincipal(r.Context(), &principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}
