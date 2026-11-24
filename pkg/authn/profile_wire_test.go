// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

type humanWireClaims struct {
	tstoken.HumanSessionClaims
	payload []byte
}

func TestExplicitProfileAcceptanceMatrix(t *testing.T) {
	x := newProfileFixture(t)
	legacy := validTokenSmithClaims("iss", []string{"svc"})
	legacy["iat"], legacy["nbf"], legacy["exp"], legacy["session_exp"] = x.claims.IssuedAt, x.claims.IssuedAt, x.claims.ExpiresAt, x.claims.ExpiresAt
	for _, enabled := range [][]tstoken.Profile{nil, {tstoken.ProfileLegacyV1}, {tstoken.ProfileHumanSessionV1}, {tstoken.ProfileLegacyV1, tstoken.ProfileHumanSessionV1}} {
		for _, input := range []struct {
			name   string
			claims jwt.Claims
			human  bool
		}{{"legacy", legacy, false}, {"human", x.claims, true}} {
			t.Run(fmt.Sprint(enabled)+"/"+input.name, func(t *testing.T) {
				// Given explicitly allowed profiles, when authenticated, then accept only the selected contract.
				o := x.opt
				o.Profiles = enabled
				want := !input.human && len(enabled) == 0
				for _, p := range enabled {
					if (p == tstoken.ProfileHumanSessionV1) == input.human {
						want = true
					}
				}
				w, ctx := serveProfile(t, o, x.sign(t, input.claims))
				if want {
					if w.Code != 204 || ctx == nil {
						t.Fatalf("enabled profile rejected: %d", w.Code)
					}
				} else if w.Code != 401 || ctx != nil {
					t.Fatal("disabled profile accepted")
				}
			})
		}
	}
}

func (c humanWireClaims) MarshalJSON() ([]byte, error) { return c.payload, nil }

func TestSignedHumanProfileConfusionNeverFallsBack(t *testing.T) {
	x := newProfileFixture(t)
	x.opt.Profiles = []tstoken.Profile{tstoken.ProfileLegacyV1, tstoken.ProfileHumanSessionV1}
	b, err := json.Marshal(x.claims)
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []struct{ old, value string }{
		{`"token_profile":"human-session-v1",`, ``},
		{`"token_profile":"human-session-v1"`, `"token_profile":null`},
		{`"token_profile":"human-session-v1"`, `"token_profile":1`},
		{`"token_profile":"human-session-v1"`, `"token_profile":"unknown"`},
		{`"token_profile":"human-session-v1"`, `"token_profile":"legacy-v1"`},
		{`"token_profile":"human-session-v1"`, `"token_profile":"human-session-v1","token_profile":"human-session-v1"`},
		{`"token_profile":"human-session-v1"`, `"token_profile":"human-session-v1","auth_factors":2`},
	} {
		t.Run(replacement.value, func(t *testing.T) {
			// Given an actually signed conflicting payload in mixed mode, when
			// authenticated, then neither profile may install an identity.
			payload := strings.Replace(string(b), replacement.old, replacement.value, 1)
			if payload == string(b) {
				t.Fatal("fixture mutation failed")
			}
			raw := x.sign(t, humanWireClaims{x.claims, []byte(payload)})
			w, ctx := serveProfile(t, x.opt, raw)
			if w.Code != 401 || ctx != nil {
				t.Fatal("conflicting profile accepted")
			}
		})
	}
}

func TestHumanOptionsSnapshotAndDuplicateAuthorization(t *testing.T) {
	x := newProfileFixture(t)
	mw, err := Middleware(x.opt)
	if err != nil {
		t.Fatal(err)
	}
	// Given retained configuration, when the caller mutates its policy and slices,
	// then the middleware still uses the original fixed trust configuration.
	x.opt.HumanSessionPolicy.ProjectID = 1
	x.opt.Profiles[0] = tstoken.ProfileLegacyV1
	x.opt.Issuers[0], x.opt.Audiences[0] = "wrong", "wrong"
	raw := x.sign(t, x.claims)
	for _, duplicates := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/nodes", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		if duplicates {
			r.Header.Add("Authorization", "Bearer "+raw)
		}
		called := false
		w := httptest.NewRecorder()
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(204) })).ServeHTTP(w, r)
		if duplicates {
			if w.Code != 401 || called {
				t.Fatal("duplicate authorization accepted")
			}
		} else if w.Code != 204 || !called {
			t.Fatal("caller mutation changed retained policy")
		}
	}
}
