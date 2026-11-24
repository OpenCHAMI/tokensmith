// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package deviceauth

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
)

type countingRouteMapper struct{ calls int }

func (m *countingRouteMapper) Map(r *http.Request, p authz.Principal) (authz.RouteDecision, error) {
	m.calls++
	return (authz.PathMethodMapper{MethodToAction: authz.MethodToActionREST()}).Map(r, p)
}

func deviceAuthPolicy(t *testing.T) *authz.Authorizer {
	t.Helper()
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range [][]string{
		{"role:viewer", "/nodes", "read"},
		{"role:operator", "/nodes", "read"},
		{"role:operator", "/nodes", "write"},
		{"role:admin", "/nodes", "read"},
		{"role:admin", "/nodes", "write"},
		{"role:admin", "/nodes", "delete"},
	} {
		if _, err := e.AddPolicy(rule); err != nil {
			t.Fatal(err)
		}
	}
	a, err := authz.NewAuthorizer(e, "deviceauth-test-policy")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestVerifiedTokenCasbinAuthorization(t *testing.T) {
	x := newTokenFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	lookup := func(kid string) (*rsa.PublicKey, error) {
		if kid != "key-1" {
			return nil, errors.New("private lookup failure")
		}
		return &x.k.private.PublicKey, nil
	}
	authenticate, err := Middleware(config(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	mapper := &countingRouteMapper{}
	authorize := authz.NewMiddleware(deviceAuthPolicy(t), mapper, authz.WithRequireAuthn(true))
	handled := 0
	var principal *authz.Principal
	handler := authenticate(authorize.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled++
		var ok bool
		principal, ok = authz.PrincipalFromContext(r.Context())
		if !ok {
			t.Fatal("verified principal missing in handler")
		}
		common, ok := authn.PrincipalFromContext(r.Context())
		if !ok || !reflect.DeepEqual(common, *principal) {
			t.Fatal("device middleware did not install common AuthN principal")
		}
		if claims, ok := authn.HumanSessionClaimsFromContext(r.Context()); !ok || claims.UserID != 207 {
			t.Fatal("device middleware did not install typed human claims")
		}
		w.WriteHeader(http.StatusNoContent)
	})))

	for _, tc := range []struct {
		name, method, role string
		want               int
	}{
		{"viewer reads", "GET", "viewer", 204},
		{"viewer cannot write", "POST", "viewer", 403},
		{"viewer cannot delete", "DELETE", "viewer", 403},
		{"operator writes", "POST", "operator", 204},
		{"operator cannot delete", "DELETE", "operator", 403},
		{"admin deletes", "DELETE", "admin", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise signed role -> strict verification -> Casbin.
			x = newTokenFixture(t)
			x.claims.IssuedAt = now.Unix()
			x.claims.NotBefore = now.Unix()
			x.claims.ExpiresAt = now.Unix() + config().TokenSeconds
			x.claims.ApprovedAt = now.Unix()
			x.claims.SessionExp = now.Unix() + config().AbsoluteSeconds
			x.claims.MembershipCheckedAt = now.Unix()
			x.claims.Role = tc.role
			raw := x.sign(t)
			mapper.calls, handled, principal = 0, 0, nil
			request := httptest.NewRequest(tc.method, "/nodes", nil)
			request.Header.Set("Authorization", "bEaReR "+raw)
			// Caller-provided context must not upgrade a verified viewer.
			request = request.WithContext(authz.SetPrincipal(request.Context(), &authz.Principal{ID: "attacker", Roles: []string{"admin"}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.want || mapper.calls != 1 {
				t.Fatalf("status=%d mapper calls=%d body=%s", response.Code, mapper.calls, response.Body.String())
			}
			if tc.want == 204 {
				if handled != 1 || principal.ID != config().Issuer+"/user/207" || !reflect.DeepEqual(principal.Roles, []string{tc.role}) {
					t.Fatalf("wrong verified principal: %#v", principal)
				}
			} else if handled != 0 {
				t.Fatal("authorization denial reached handler")
			}
		})
	}

	x = newTokenFixture(t)
	x.claims.IssuedAt = now.Unix()
	x.claims.NotBefore = now.Unix()
	x.claims.ExpiresAt = now.Unix() + config().TokenSeconds
	x.claims.ApprovedAt = now.Unix()
	x.claims.SessionExp = now.Unix() + config().AbsoluteSeconds
	x.claims.MembershipCheckedAt = now.Unix()
	raw := x.sign(t)
	claims, err := x.k.Verify(raw, config(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, header string
		duplicate    bool
		mutate       func(*Claims)
	}{
		{name: "missing bearer"},
		{name: "malformed bearer", header: "Basic private-secret"},
		{name: "invalid token", header: "Bearer private-invalid-token"},
		{name: "duplicate authorization", header: "Bearer " + raw, duplicate: true},
		{name: "tampered signature", header: "Bearer " + raw + "tampered"},
		{name: "expired", mutate: func(c *Claims) {
			// Otherwise valid lifetime/session relationships, inside parser
			// clock leeway but beyond the contract's strict expiry boundary.
			c.IssuedAt -= 100
			c.NotBefore -= 100
			c.ApprovedAt -= 100
			c.SessionExp -= 100
			c.MembershipCheckedAt -= 100
			c.ExpiresAt = now.Unix() - 1
		}},
		{name: "wrong issuer", mutate: func(c *Claims) { c.Issuer = "https://untrusted.example" }},
		{name: "wrong project", mutate: func(c *Claims) { c.ProjectID++ }},
		{name: "wrong class", mutate: func(c *Claims) { c.Class = "machine" }},
		{name: "unknown role", mutate: func(c *Claims) { c.Role = "root" }},
		{name: "stale membership", mutate: func(c *Claims) {
			c.ApprovedAt -= 100
			c.SessionExp -= 100
			c.MembershipCheckedAt -= 91
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			if tc.mutate != nil {
				copy := *claims
				tc.mutate(&copy)
				raw, err := x.k.Sign(copy)
				if err != nil {
					t.Fatal(err)
				}
				header = "Bearer " + raw
			}
			mapper.calls, handled = 0, 0
			request := httptest.NewRequest("DELETE", "/nodes", nil)
			request.Header.Set("Authorization", header)
			if tc.duplicate {
				request.Header.Add("Authorization", "Bearer "+raw)
			}
			request = request.WithContext(authz.SetPrincipal(request.Context(), &authz.Principal{ID: "attacker", Roles: []string{"admin"}}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 401 || mapper.calls != 0 || handled != 0 {
				t.Fatalf("invalid authentication reached authorization: status=%d maps=%d handlers=%d", response.Code, mapper.calls, handled)
			}
			if response.Body.String() != "invalid token\n" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("authentication failure was not sanitized and non-cacheable")
			}
		})
	}
}

func TestDeviceAuthPrincipalFailsClosedWithoutTrustedLookup(t *testing.T) {
	x := newTokenFixture(t)
	raw := x.sign(t)
	for _, lookup := range []func(string) (*rsa.PublicKey, error){
		nil,
		func(string) (*rsa.PublicKey, error) { return nil, nil },
		func(string) (*rsa.PublicKey, error) { return nil, errors.New("private credential in lookup error") },
	} {
		p, err := VerifyPrincipal(raw, config(), x.now, lookup)
		if err != ErrDenied || p.ID != "" || len(p.Roles) != 0 {
			t.Fatalf("untrusted lookup returned principal=%#v err=%v", p, err)
		}
	}
	if _, err := Middleware(config(), nil); err != ErrDenied {
		t.Fatal("missing trusted lookup accepted")
	}
	bad := config()
	bad.ClusterIssuer = ""
	if _, err := Middleware(bad, func(string) (*rsa.PublicKey, error) { return &x.k.private.PublicKey, nil }); err != ErrDenied {
		t.Fatal("invalid configuration accepted")
	}
}
