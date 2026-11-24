// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package deviceauth

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/token"
)

// VerifyPrincipal applies the complete device-authorization token contract before
// mapping the verified subject and role into the existing authorization principal.
// lookup must use keys trusted for c.ClusterIssuer, never token-selected URLs.
// The caller must bound clock error and key-cache lifetime as required by Verify.
func VerifyPrincipal(raw string, c Config, now time.Time, lookup func(string) (*rsa.PublicKey, error)) (authz.Principal, error) {
	if lookup == nil {
		return authz.Principal{}, ErrDenied
	}
	claims, err := Verify(raw, c, now, lookup)
	if err != nil {
		return authz.Principal{}, ErrDenied
	}
	return authz.Principal{ID: claims.Subject, Roles: []string{claims.Role}}, nil
}

// Middleware forwards the human-only device contract to the common AuthN path.
// Deprecated: use authn.Middleware with explicit human-session policy.
func Middleware(c Config, lookup func(string) (*rsa.PublicKey, error)) (func(http.Handler) http.Handler, error) {
	c = c.clone()
	if c.Validate() != nil || lookup == nil {
		return nil, ErrDenied
	}
	p := c.ConsumerPolicy()
	mw, err := authn.Middleware(authn.Options{
		Profiles: []token.Profile{token.ProfileHumanSessionV1}, HumanSessionPolicy: &p,
		Issuers: []string{c.ClusterIssuer}, Audiences: []string{c.Audience},
		HumanSessionKeyLookup: func(_ context.Context, kid string) (*rsa.PublicKey, error) { return lookup(kid) },
	})
	if err != nil {
		return nil, ErrDenied
	}
	return mw, nil
}
