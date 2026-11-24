// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package deviceauth

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestProfileWrapperRejectsUnmarkedAndWrongMarker(t *testing.T) {
	x := newTokenFixture(t)
	b, err := json.Marshal(x.claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"", "legacy-v1", "unknown"} {
		t.Run(marker, func(t *testing.T) {
			// Given a correctly signed token with the wrong profile, when verified, then deny without fallback.
			var claims jwt.MapClaims
			if err := json.Unmarshal(b, &claims); err != nil {
				t.Fatal(err)
			}
			delete(claims, "token_profile")
			if marker != "" {
				claims["token_profile"] = marker
			}
			j := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
			j.Header["kid"] = "key-1"
			raw, err := j.SignedString(x.k.private)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.k.Verify(raw, config(), x.now); !errors.Is(err, ErrDenied) {
				t.Fatalf("wrong profile accepted: %v", err)
			}
		})
	}
}

func TestConsumerPolicyExcludesBrokerProvisioning(t *testing.T) {
	// Given a valid broker configuration, when projecting consumer policy, then
	// credentials and role provisioning cannot affect the consumer contract.
	c := config()
	want := c.ConsumerPolicy()
	c.ClientID, c.VerifierFile = "", ""
	c.GitLabRoleMapping = map[string]string{"invalid": "invalid"}
	if got := c.ConsumerPolicy(); got != want || got.Validate() != nil {
		t.Fatalf("consumer depends on broker provisioning: %+v", got)
	}
}

func TestAuthorityEmitsHumanSessionProfile(t *testing.T) {
	// Given a successful device approval, when issued, then the signed payload carries the human profile.
	x := setup(t)
	result, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Parse(result.Access, func(*jwt.Token) (any, error) { return &x.k.private.PublicKey, nil }, jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{"PS256"}))
	if err != nil {
		t.Fatal(err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || claims["token_profile"] != "human-session-v1" {
		t.Fatal("issuer omitted signed profile")
	}
}
