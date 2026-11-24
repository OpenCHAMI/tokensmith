// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/openchami/tokensmith/pkg/authn"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/deviceauth"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/rs/zerolog"
)

type profileE2E struct {
	t           *testing.T
	service     *TokenService
	policy      deviceauth.Config
	broker      *httptest.Server
	resource    *httptest.Server
	ctx         context.Context
	revokes     atomic.Int64
	memberCalls atomic.Int64
}

func newProfileE2E(t *testing.T) *profileE2E {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	x := &profileE2E{t: t, ctx: ctx}
	var origin string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		send := func(v any) {
			if err := json.NewEncoder(w).Encode(v); err != nil {
				t.Error(err)
			}
		}
		switch r.URL.Path {
		case "/oauth/authorize_device":
			if r.Form.Get("client_id") != "application" || r.Form.Get("scope") != "read_user" {
				t.Error("unexpected grant request")
			}
			send(deviceauth.Device{Code: "synthetic-device", UserCode: "USER", URI: origin + "/oauth/device", Expires: 300, Interval: 1})
		case "/oauth/token":
			if r.Form.Get("device_code") != "synthetic-device" {
				t.Error("wrong private device code")
			}
			send(deviceauth.Credential{Access: "synthetic-access", Refresh: "synthetic-refresh", Type: "Bearer", Scope: "read_user", Expires: 7200})
		case "/oauth/token/info":
			if r.Header.Get("Authorization") != "Bearer synthetic-access" {
				t.Error("wrong OAuth credential")
			}
			send(map[string]any{"application": map[string]string{"uid": "application"}, "resource_owner_id": int64(9007199254740995), "scope": []string{"read_user"}, "created_at": time.Now().Unix() - 1, "expires_in": 7200})
		case "/api/v4/user":
			send(map[string]any{"id": int64(9007199254740995), "state": "active"})
		case "/api/v4/projects/701/members/all/9007199254740995":
			if r.Header.Get("Authorization") != "Bearer synthetic-verifier" {
				t.Error("wrong private membership credential")
			}
			x.memberCalls.Add(1)
			send(map[string]any{"id": int64(9007199254740995), "access_level": 20})
		case "/oauth/revoke":
			if r.Form.Get("token") != "synthetic-access" {
				t.Error("wrong revoked credential")
			}
			x.revokes.Add(1)
			w.WriteHeader(200)
		default:
			t.Error("unexpected provider endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(upstream.Close)
	origin = upstream.URL
	// Trust only the fixture CA without adding a product clock or transport API.
	previous := http.DefaultTransport
	http.DefaultTransport = upstream.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	s, config := deviceAuthServiceFixture(t)
	config.Issuer = origin
	if err := s.ConfigureDeviceAuth(config); err != nil {
		t.Fatal(err)
	}
	x.service, x.policy = s, *config
	x.broker = httptest.NewTLSServer(s.newRouter(zerolog.Nop()))
	t.Cleanup(x.broker.Close)
	x.resource = x.protected(false)
	return x
}

func (x *profileE2E) protected(legacyOnly bool) *httptest.Server {
	x.t.Helper()
	p := x.policy.ConsumerPolicy()
	opt := authn.Options{Issuers: []string{p.ClusterIssuer}, Audiences: []string{p.Audience}, JWKSURLs: []string{x.broker.URL + "/.well-known/jwks.json"}, HTTPClient: x.broker.Client()}
	if !legacyOnly {
		opt.Profiles = []token.Profile{token.ProfileHumanSessionV1}
		opt.HumanSessionPolicy = &p
	}
	authenticate, err := authn.Middleware(opt)
	if err != nil {
		x.t.Fatal(err)
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
		x.t.Fatal(err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		x.t.Fatal(err)
	}
	if _, err := e.AddPolicy("role:viewer", "/nodes", "read"); err != nil {
		x.t.Fatal(err)
	}
	a, err := authz.NewAuthorizer(e, "profiles-e2e")
	if err != nil {
		x.t.Fatal(err)
	}
	authorize := authz.NewMiddleware(a, authz.PathMethodMapper{MethodToAction: authz.MethodToActionREST()}, authz.WithMode(authz.ModeEnforce), authz.WithRequireAuthn(true))
	resource := httptest.NewServer(authenticate(authorize.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := authn.HumanSessionClaimsFromContext(r.Context())
		if !ok || c.UserID != 9007199254740995 || c.Role != "viewer" {
			x.t.Error("verified identity missing or rounded")
		}
		w.WriteHeader(200)
		if _, err := w.Write([]byte("nodes-ok")); err != nil {
			x.t.Error(err)
		}
	}))))
	x.t.Cleanup(resource.Close)
	return resource
}

type profileHTTPRequest struct {
	method, url, body, bearer string
	status                    int
}

func (x *profileE2E) request(client *http.Client, in profileHTTPRequest) []byte {
	x.t.Helper()
	r, err := http.NewRequestWithContext(x.ctx, in.method, in.url, strings.NewReader(in.body))
	if err != nil {
		x.t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if in.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+in.bearer)
	}
	response, err := client.Do(r)
	if err != nil {
		x.t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			x.t.Error(err)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		x.t.Fatal(err)
	}
	if response.StatusCode != in.status {
		x.t.Fatalf("%s %s status=%d want=%d body=%s", in.method, r.URL.Path, response.StatusCode, in.status, body)
	}
	if r.URL.Path == "/nodes" {
		x.t.Logf("%s /nodes -> %d %s", in.method, response.StatusCode, strings.TrimSpace(string(body)))
	}
	return body
}

func (x *profileE2E) brokerCall(path, bearer string, status int) []byte {
	return x.request(x.broker.Client(), profileHTTPRequest{"POST", x.broker.URL + path, `{}`, bearer, status})
}
