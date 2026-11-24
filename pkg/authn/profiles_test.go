// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authz"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

type profileFixture struct {
	key    *rsa.PrivateKey
	claims tstoken.HumanSessionClaims
	opt    Options
}

func newProfileFixture(t *testing.T) profileFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	p := &tstoken.HumanSessionPolicy{ClusterIssuer: "iss", Audience: "svc", GitLabIssuer: "https://gitlab.test", ProjectID: 9007199254740993, CacheSeconds: 90, TokenSeconds: 180, SkewSeconds: 30, AbsoluteSeconds: 36000}
	c := tstoken.HumanSessionClaims{TokenProfile: tstoken.ProfileHumanSessionV1, Issuer: "iss", Audience: []string{"svc"}, Subject: p.GitLabIssuer + "/user/9007199254740995", UserID: 9007199254740995, ProjectID: p.ProjectID, GitLabIssuer: p.GitLabIssuer, Class: "human", Role: "viewer", ID: "human-jti", SessionID: "session", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Unix() + 180, ApprovedAt: now.Unix(), SessionExp: now.Unix() + 36000, MembershipCheckedAt: now.Unix()}
	return profileFixture{key, c, Options{Profiles: []tstoken.Profile{tstoken.ProfileHumanSessionV1}, HumanSessionPolicy: p, Issuers: []string{"iss"}, Audiences: []string{"svc"}, StaticKeys: []crypto.PublicKey{&key.PublicKey}, now: func() time.Time { return now }}}
}

func (x profileFixture) sign(t *testing.T, c jwt.Claims) string {
	t.Helper()
	j := jwt.NewWithClaims(jwt.SigningMethodPS256, c)
	setRFC7638KID(t, j, &x.key.PublicKey)
	raw, err := j.SignedString(x.key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func serveProfile(t *testing.T, opt Options, raw string) (*httptest.ResponseRecorder, context.Context) {
	t.Helper()
	mw, err := Middleware(opt)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/nodes", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	var ctx context.Context
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ctx = r.Context(); w.WriteHeader(204) })).ServeHTTP(w, r)
	return w, ctx
}

func TestHumanProfilesRequireExplicitSafeConfiguration(t *testing.T) {
	x := newProfileFixture(t)
	for name, mutate := range map[string]func(*Options){
		"unknown":             func(o *Options) { o.Profiles = []tstoken.Profile{"unknown"} },
		"duplicate":           func(o *Options) { o.Profiles = append(o.Profiles, o.Profiles[0]) },
		"missing policy":      func(o *Options) { o.HumanSessionPolicy = nil },
		"invalid policy":      func(o *Options) { p := *o.HumanSessionPolicy; p.TokenSeconds = 0; o.HumanSessionPolicy = &p },
		"issuer disabled":     func(o *Options) { o.DisableIssuerValidation = true },
		"audience disabled":   func(o *Options) { o.DisableAudienceValidation = true },
		"multiple issuers":    func(o *Options) { o.Issuers = []string{"iss", "other"} },
		"multiple audiences":  func(o *Options) { o.Audiences = []string{"svc", "other"} },
		"mismatched issuer":   func(o *Options) { o.Issuers = []string{"other"} },
		"mismatched audience": func(o *Options) { o.Audiences = []string{"other"} },
	} {
		t.Run(name, func(t *testing.T) {
			// Given unsafe profile configuration, when constructed, then reject it.
			o := x.opt
			mutate(&o)
			if _, err := Middleware(o); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}

func TestHumanContextPreservesIdentityAndIgnoresLegacyMapper(t *testing.T) {
	x := newProfileFixture(t)
	x.opt.Mapper = func(context.Context, *jwt.Token, jwt.MapClaims) (authz.Principal, error) {
		t.Fatal("human called legacy mapper")
		return authz.Principal{}, nil
	}
	// Given a signed large identity, when authenticated, then both contexts agree.
	w, ctx := serveProfile(t, x.opt, x.sign(t, x.claims))
	if w.Code != 204 || ctx == nil {
		t.Fatalf("human rejected: %d", w.Code)
	}
	p, ok := PrincipalFromContext(ctx)
	a, aok := authz.PrincipalFromContext(ctx)
	if !ok || !aok || p.ID != x.claims.Subject || !reflect.DeepEqual(p, *a) || !reflect.DeepEqual(p.Roles, []string{"viewer"}) {
		t.Fatalf("wrong principals: %+v %+v", p, a)
	}
	c, ok := HumanSessionClaimsFromContext(ctx)
	if !ok || c.UserID != 9007199254740995 || c.ProjectID != 9007199254740993 {
		t.Fatal("identity precision lost")
	}
	c.Audience[0] = "mutated"
	c.UserID = 1
	again, _ := HumanSessionClaimsFromContext(ctx)
	if again.Audience[0] != "svc" || again.UserID != x.claims.UserID {
		t.Fatal("typed context is mutable")
	}
	m, ok := VerifiedClaimsFromContext(ctx)
	if !ok || m["gitlab_user_id"] != json.Number("9007199254740995") {
		t.Fatal("map identity rounded")
	}
	for _, name := range []string{"auth_time", "amr", "acr", "auth_factors"} {
		if _, exists := m[name]; exists {
			t.Fatalf("fabricated assurance: %s", name)
		}
	}
}

func TestProfileAcceptanceAndRevocation(t *testing.T) {
	x := newProfileFixture(t)
	for name, mutate := range map[string]func(*Options, *tstoken.HumanSessionClaims){
		"default legacy": func(o *Options, c *tstoken.HumanSessionClaims) { o.Profiles = nil },
		"unmarked":       func(o *Options, c *tstoken.HumanSessionClaims) { c.TokenProfile = "" },
		"legacy marker":  func(o *Options, c *tstoken.HumanSessionClaims) { c.TokenProfile = tstoken.ProfileLegacyV1 },
		"wrong audience": func(o *Options, c *tstoken.HumanSessionClaims) { c.Audience = []string{"other"} },
		"extra audience": func(o *Options, c *tstoken.HumanSessionClaims) { c.Audience = []string{"svc", "other"} },
		"wrong issuer":   func(o *Options, c *tstoken.HumanSessionClaims) { c.Issuer = "other" },
		"wrong project":  func(o *Options, c *tstoken.HumanSessionClaims) { c.ProjectID++ },
		"expiry equals now": func(o *Options, c *tstoken.HumanSessionClaims) {
			o.now = func() time.Time { return time.Unix(c.ExpiresAt, 0) }
		},
		"revoked": func(o *Options, c *tstoken.HumanSessionClaims) {
			o.RevocationChecker = revocationCheckerFunc(func(jti string) bool {
				if jti != "human-jti" {
					t.Fatal("wrong jti")
				}
				return true
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Given an invalid signed contract, when authenticated, then never call the resource.
			o, c := x.opt, x.claims
			mutate(&o, &c)
			w, ctx := serveProfile(t, o, x.sign(t, c))
			if w.Code != 401 || ctx != nil {
				t.Fatalf("rejection failed: %d", w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("unsafe failure headers")
			}
		})
	}
	// Given mixed mode, when a valid legacy token is received, then only its mapper runs.
	o := x.opt
	o.Profiles = []tstoken.Profile{tstoken.ProfileLegacyV1, tstoken.ProfileHumanSessionV1}
	o.now = func() time.Time { return time.Unix(150, 0) }
	o.Mapper = func(context.Context, *jwt.Token, jwt.MapClaims) (authz.Principal, error) {
		return authz.Principal{ID: "mapped-legacy"}, nil
	}
	w, ctx := serveProfile(t, o, x.sign(t, validTokenSmithClaims("iss", []string{"svc"})))
	if w.Code != 204 {
		t.Fatalf("mixed legacy: %d", w.Code)
	}
	p, _ := PrincipalFromContext(ctx)
	if p.ID != "mapped-legacy" {
		t.Fatal("legacy mapper ignored")
	}
	if _, ok := HumanSessionClaimsFromContext(ctx); ok {
		t.Fatal("legacy acquired human identity")
	}
}
