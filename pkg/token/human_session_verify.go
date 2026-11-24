// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// HumanSessionVerification binds a trusted issuer policy to its clock and key source.
// Lookup must use only keys provisioned for Policy.ClusterIssuer, never token URLs.
type HumanSessionVerification struct {
	Policy HumanSessionPolicy
	Now    time.Time
	Lookup func(context.Context, string) (*rsa.PublicKey, error)
}

// VerifyHumanSession verifies one explicitly marked human session, without fallback.
func VerifyHumanSession(ctx context.Context, raw string, verification HumanSessionVerification) (*HumanSessionClaims, error) {
	if len(raw) > 8192 {
		return nil, ErrHumanSessionDenied
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHumanSessionDenied, err)
	}
	p := verification.Policy
	profile, err := SelectProfile(raw)
	if err != nil || profile != ProfileHumanSessionV1 || p.Validate() != nil || verification.Lookup == nil {
		return nil, ErrHumanSessionDenied
	}
	var claims HumanSessionClaims
	_, err = jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || t.Header["typ"] != "JWT" {
			return nil, ErrHumanSessionDenied
		}
		key, err := verification.Lookup(ctx, kid)
		if err != nil {
			return nil, err
		}
		if key == nil || key.N == nil || key.N.BitLen() < 2048 || key.E < 3 {
			return nil, ErrHumanSessionDenied
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"PS256"}),
		jwt.WithIssuer(p.ClusterIssuer),
		jwt.WithAudience(p.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Duration(p.SkewSeconds)*time.Second),
		jwt.WithTimeFunc(func() time.Time { return verification.Now }),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHumanSessionDenied, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHumanSessionDenied, err)
	}
	if err := claims.ValidateAt(p, verification.Now); err != nil {
		return nil, err
	}
	return &claims, nil
}
