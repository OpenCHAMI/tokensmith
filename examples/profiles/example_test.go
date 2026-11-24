// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package profiles_test

import (
	"fmt"
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/token"
)

func Example() {
	policy := token.HumanSessionPolicy{
		ClusterIssuer: "https://tokens.example.org", Audience: "nodes",
		GitLabIssuer: "https://gitlab.example.org", ProjectID: 123,
		CacheSeconds: 90, TokenSeconds: 180, SkewSeconds: 30, AbsoluteSeconds: 36000,
	}
	authenticate, err := authn.Middleware(authn.Options{
		Profiles: []token.Profile{token.ProfileHumanSessionV1}, HumanSessionPolicy: &policy,
		Issuers: []string{policy.ClusterIssuer}, Audiences: []string{policy.Audience},
		JWKSURLs: []string{"https://tokens.example.org/.well-known/jwks.json"},
	})
	if err != nil {
		panic(err)
	}
	m, err := model.NewModelFromString(`[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act`)
	if err != nil {
		panic(err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		panic(err)
	}
	if _, err := e.AddPolicy("role:viewer", "/nodes", "read"); err != nil {
		panic(err)
	}
	a, err := authz.NewAuthorizer(e, "nodes-v1")
	if err != nil {
		panic(err)
	}
	authorize := authz.NewMiddleware(a, authz.PathMethodMapper{MethodToAction: authz.MethodToActionREST()}, authz.WithMode(authz.ModeEnforce), authz.WithRequireAuthn(true))
	nodes := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authn.HumanSessionClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "missing verified human", http.StatusUnauthorized)
			return
		}
		if _, err := fmt.Fprintln(w, claims.UserID); err != nil {
			panic(err)
		}
	})
	handler := authenticate(authorize.Handler(nodes))
	fmt.Println(handler != nil)
	// Output: true
}
