// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestClaimsLegacySessionBoundary(t *testing.T) {
	// Given a complete legacy session with its original expiry ordering.
	now := time.Unix(1800000000, 0)
	c := TSClaims{RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "cluster", Subject: "user", Audience: []string{"resource"},
		IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}, AuthLevel: "IAL2", AuthFactors: 2, AuthMethods: []string{"password", "otp"},
		SessionID: "session", SessionExp: now.Unix() + 3600, AuthEvents: []string{"login"}}
	// When validating at issuance, then the original contract accepts it.
	if err := c.ValidateAt(true, now); err != nil {
		t.Fatal(err)
	}
	// Given a session deadline beyond the token, when validated, then reject it.
	c.SessionExp++
	if err := c.ValidateAt(true, now); err == nil {
		t.Fatal("legacy session ordering relaxed")
	}
	// Given missing assurance, when validated, then reject it independently.
	c.SessionExp--
	c.AuthFactors = 1
	if err := c.ValidateAt(true, now); err == nil {
		t.Fatal("legacy assurance relaxed")
	}
}
