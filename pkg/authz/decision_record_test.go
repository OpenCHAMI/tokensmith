package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func newTestAuthorizerObs(t *testing.T, allow bool) *Authorizer {
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
		t.Fatalf("model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}
	if allow {
		_, _ = e.AddPolicy("role:admin", "obj", "act")
	}
	a, err := NewAuthorizer(e, "pv-obs-test")
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	return a
}

func TestMiddleware_OnDecision_Shadow_CalledOnceAndNoJWT(t *testing.T) {
	t.Parallel()

	a := newTestAuthorizerObs(t, false)

	jwtRaw := "header.payload.signature"
	rid := "req-123"

	var calls int
	var got DecisionRecord
	mw := NewMiddleware(a, testMapper{rd: RouteDecision{Mapped: true, Object: "obj", Action: "act"}},
		WithMode(ModeShadow),
		WithOnDecision(func(_ctx context.Context, rec DecisionRecord) {
			calls++
			got = rec
		}),
		WithIncludeRolesInDecisionRecord(true),
	)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	r.Header.Set("Authorization", "Bearer "+jwtRaw)
	r = r.WithContext(SetPrincipal(r.Context(), &Principal{ID: "u", Roles: []string{"admin"}}))
	r = r.WithContext(ContextWithRequestID(r.Context(), rid))

	rr := httptest.NewRecorder()
	mw.Handler(next).ServeHTTP(rr, r)

	if rr.Code != 200 {
		t.Fatalf("status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("hook calls: got %d want 1", calls)
	}

	if got.Mode != ModeShadow {
		t.Fatalf("mode: got %q", got.Mode)
	}
	if got.PolicyVersion != "pv-obs-test" {
		t.Fatalf("policy version: got %q", got.PolicyVersion)
	}
	if got.PrincipalID != "u" {
		t.Fatalf("principal id: got %q", got.PrincipalID)
	}
	if got.RolesCount != 1 {
		t.Fatalf("roles_count: got %d", got.RolesCount)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "admin" {
		t.Fatalf("roles: got %#v", got.Roles)
	}
	if got.Object != "obj" || got.Action != "act" {
		t.Fatalf("input: got %q/%q", got.Object, got.Action)
	}
	if got.Method != http.MethodGet || got.Path != "/protected" {
		t.Fatalf("request: got %q %q", got.Method, got.Path)
	}
	if got.RequestID != rid {
		t.Fatalf("request_id: got %q", got.RequestID)
	}

	// Redaction guarantee: DecisionRecord must never contain raw JWT.
	joined := strings.Join([]string{got.PrincipalID, got.PrincipalType, strings.Join(got.Roles, ","), got.Object, got.Action, got.Domain, string(got.Decision), string(got.Reason), string(got.Mode), got.PolicyVersion, got.Method, got.Path, got.RequestID}, "|")
	if strings.Contains(joined, jwtRaw) {
		t.Fatalf("decision record contains raw jwt")
	}
}

func TestMiddleware_OnDecision_Off_NotCalled(t *testing.T) {
	t.Parallel()

	a := newTestAuthorizerObs(t, true)
	var calls int
	mw := NewMiddleware(a, testMapper{rd: RouteDecision{Mapped: true, Object: "obj", Action: "act"}},
		WithMode(ModeOff),
		WithOnDecision(func(_ctx context.Context, rec DecisionRecord) {
			_ = rec
			calls++
		}),
	)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	r := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	r = r.WithContext(SetPrincipal(r.Context(), &Principal{ID: "u", Roles: []string{"admin"}}))

	rr := httptest.NewRecorder()
	mw.Handler(next).ServeHTTP(rr, r)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d", rr.Code)
	}
	if calls != 0 {
		t.Fatalf("hook calls: got %d want 0", calls)
	}
}
