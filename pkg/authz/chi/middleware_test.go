package chi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	model "github.com/casbin/casbin/v2/model"
	"github.com/openchami/tokensmith/pkg/authz"
)

type testMetrics struct {
	calls []struct {
		decision       authz.Decision
		object, action string
	}
}

func (m *testMetrics) IncAuthzDecision(d authz.Decision, object, action string) {
	m.calls = append(m.calls, struct {
		decision       authz.Decision
		object, action string
	}{d, object, action})
}

func mustAuthorizer(t *testing.T) *authz.Authorizer {
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
	_, err = e.AddPolicy("role:viewer", "metadata:nodes", "read")
	if err != nil {
		t.Fatal(err)
	}

	a, err := authz.NewAuthorizer(e, "pv-test")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDenyByDefault_NoRequireOrPublic(t *testing.T) {
	a := mustAuthorizer(t)
	metrics := &testMetrics{}
	mw := New(a, WithMetrics(metrics))

	h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	// missing principal and missing requirement => deny-by-default is authz, but
	// we will hit missing requirement first and return 403.
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
	if len(metrics.calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(metrics.calls))
	}
	if metrics.calls[0].decision != authz.DecisionIndeterminate {
		t.Fatalf("expected indeterminate, got %s", metrics.calls[0].decision)
	}
}

func TestPublicRoute_SkipsAuthz(t *testing.T) {
	a := mustAuthorizer(t)
	metrics := &testMetrics{}
	mw := New(a, WithMetrics(metrics))

	h := SkipAuthz()(mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	if len(metrics.calls) != 0 {
		t.Fatalf("expected 0 metrics calls, got %d", len(metrics.calls))
	}
}

func TestRequire_MissingPrincipal_401ByDefault(t *testing.T) {
	a := mustAuthorizer(t)
	mw := New(a)

	h := Require("metadata:nodes", "read")(mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestRequire_Allowed(t *testing.T) {
	a := mustAuthorizer(t)
	metrics := &testMetrics{}
	mw := New(a, WithMetrics(metrics))

	h := Require("metadata:nodes", "read")(mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	p := &authz.Principal{ID: "u1", Roles: []string{"viewer"}}
	req = req.WithContext(SetPrincipal(req.Context(), p))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, rr.Code)
	}
	if len(metrics.calls) != 1 {
		t.Fatalf("expected 1 metrics call, got %d", len(metrics.calls))
	}
	if metrics.calls[0].decision != authz.DecisionAllow {
		t.Fatalf("expected allow, got %s", metrics.calls[0].decision)
	}
	if metrics.calls[0].object != "metadata:nodes" || metrics.calls[0].action != "read" {
		t.Fatalf("expected labels metadata:nodes/read, got %s/%s", metrics.calls[0].object, metrics.calls[0].action)
	}
}

func TestRequire_Denied(t *testing.T) {
	a := mustAuthorizer(t)
	mw := New(a)

	h := Require("metadata:nodes", "delete")(mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodDelete, "/nodes", nil)
	p := &authz.Principal{ID: "u1", Roles: []string{"viewer"}}
	req = req.WithContext(SetPrincipal(req.Context(), p))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected %d, got %d", http.StatusForbidden, rr.Code)
	}
}

func TestPrincipalFromContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := PrincipalFromContext(ctx); ok {
		t.Fatal("expected no principal")
	}

	p := &authz.Principal{ID: "x", Roles: []string{"admin"}}
	ctx = SetPrincipal(ctx, p)
	p2, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("expected principal")
	}
	if p2.ID != "x" {
		t.Fatalf("expected id x, got %s", p2.ID)
	}
}
