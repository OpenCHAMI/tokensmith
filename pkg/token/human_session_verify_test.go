// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyHumanSession(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, p, now := humanFixture()
	opts := HumanSessionVerification{Policy: p, Now: now, Lookup: func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
		if kid != "key-1" {
			return nil, ErrHumanSessionDenied
		}
		return &key.PublicKey, nil
	}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		kid    any
		typ    any
		extra  string
		want   bool
	}{
		{"valid", jwt.SigningMethodPS256, "key-1", "JWT", "", true},
		{"oversized", jwt.SigningMethodPS256, "key-1", "JWT", `,"padding":"` + strings.Repeat("a", 9000) + `"`, false},
		{"RS256", jwt.SigningMethodRS256, "key-1", "JWT", "", false},
		{"HS256", jwt.SigningMethodHS256, "key-1", "JWT", "", false},
		{"none", jwt.SigningMethodNone, "key-1", "JWT", "", false},
		{"missing kid", jwt.SigningMethodPS256, nil, "JWT", "", false},
		{"numeric kid", jwt.SigningMethodPS256, 42, "JWT", "", false},
		{"unknown kid", jwt.SigningMethodPS256, "other", "JWT", "", false},
		{"wrong typ", jwt.SigningMethodPS256, "key-1", "JWE", "", false},
		{"missing typ", jwt.SigningMethodPS256, "key-1", nil, "", false},
		{"legacy extension", jwt.SigningMethodPS256, "key-1", "JWT", `,"auth_time":0`, false},
		{"duplicate marker", jwt.SigningMethodPS256, "key-1", "JWT", `,"token_profile":"human-session-v1"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given an actually signed adversarial payload, when verified, then enforce the selected contract.
			payload := string(b[:len(b)-1]) + tc.extra + "}"
			j := jwt.NewWithClaims(tc.method, rawClaims{HumanSessionClaims: c, payload: []byte(payload)})
			j.Header["kid"] = tc.kid
			j.Header["typ"] = tc.typ
			var signingKey any = key
			switch tc.method {
			case jwt.SigningMethodHS256:
				signingKey = []byte("synthetic")
			case jwt.SigningMethodNone:
				signingKey = jwt.UnsafeAllowNoneSignatureType
			}
			raw, err := j.SignedString(signingKey)
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyHumanSession(context.Background(), raw, opts)
			if (err == nil) != tc.want {
				t.Fatalf("acceptance: %v", err)
			}
			if tc.want && (got.UserID != c.UserID || got.ProjectID != c.ProjectID) {
				t.Fatal("identity precision lost")
			}
		})
	}
	j := jwt.NewWithClaims(jwt.SigningMethodPS256, c)
	j.Header["kid"] = "key-1"
	raw, err := j.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*HumanSessionVerification){
		func(o *HumanSessionVerification) { o.Lookup = nil },
		func(o *HumanSessionVerification) {
			o.Lookup = func(context.Context, string) (*rsa.PublicKey, error) { return nil, nil }
		},
		func(o *HumanSessionVerification) { o.Now = now.Add(180 * 1000000000) },
	} {
		bad := opts
		mutate(&bad)
		if _, err := VerifyHumanSession(context.Background(), raw, bad); err == nil {
			t.Fatal("accepted invalid verification options/expiry")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyHumanSession(ctx, raw, opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := VerifyHumanSession(context.Background(), raw+"tampered", opts); err == nil {
		t.Fatal("signature tampering accepted")
	}
}

func TestVerifyHumanSessionSignedMalformedClaims(t *testing.T) {
	// Given valid signatures, malformed claims must reach the profile/claim checks.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c, p, now := humanFixture()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []struct{ old, value string }{
		{`"token_profile":"human-session-v1",`, ``},
		{`"token_profile":"human-session-v1"`, `"token_profile":null`},
		{`"token_profile":"human-session-v1"`, `"token_profile":1`},
		{`"token_profile":"human-session-v1"`, `"token_profile":"unknown"`},
		{`"token_profile":"human-session-v1"`, `"token_profile":"legacy-v1"`},
		{`"gitlab_user_id":9007199254740995`, `"gitlab_user_id":9007199254740996`},
		{`"gitlab_user_id":9007199254740995`, `"gitlab_user_id":9223372036854775808`},
		{`"gitlab_user_id":9007199254740995`, `"gitlab_user_id":1.5`},
		{`"gitlab_user_id":9007199254740995`, `"gitlab_user_id":"9007199254740995"`},
		{`"gitlab_project_id":9007199254740993`, `"gitlab_project_id":null`},
		{`"role":"viewer"`, `"role":"owner"`},
	} {
		t.Run(replacement.value, func(t *testing.T) {
			payload := strings.Replace(string(b), replacement.old, replacement.value, 1)
			if payload == string(b) {
				t.Fatal("fixture mutation did not apply")
			}
			j := jwt.NewWithClaims(jwt.SigningMethodPS256, rawClaims{c, []byte(payload)})
			j.Header["kid"] = "key-1"
			raw, err := j.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			// When verifying, then deny even though the signature is valid.
			got, err := VerifyHumanSession(context.Background(), raw, HumanSessionVerification{
				Policy: p, Now: now,
				Lookup: func(context.Context, string) (*rsa.PublicKey, error) { return &key.PublicKey, nil },
			})
			if got != nil || !errors.Is(err, ErrHumanSessionDenied) {
				t.Fatalf("invalid claims accepted: %v", err)
			}
		})
	}
}

type rawClaims struct {
	HumanSessionClaims
	payload []byte
}

func (c rawClaims) MarshalJSON() ([]byte, error) { return c.payload, nil }
