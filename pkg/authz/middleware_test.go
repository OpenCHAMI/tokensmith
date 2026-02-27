package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

type testMapper struct {
	rd  RouteDecision
	err error
}

func (m testMapper) Map(_ *http.Request, _ Principal) (RouteDecision, error) { return m.rd, m.err }

func newTestAuthorizerMW(t *testing.T, allow bool) *Authorizer {
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
	// policyVersion can be any non-empty for tests.
	a, err := NewAuthorizer(e, "pvtest")
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	return a
}

func TestAuthzMiddleware_DecisionMatrix(t *testing.T) {
	t.Parallel()

	type tc struct {
		name       string
		mode       Mode
		requireN   bool
		public     bool
		principal  *Principal
		mapped     bool
		mapErr     error
		authzAllow bool
		wantCode   int
		wantReason Reason
		wantCalled bool
	}

	cases := []tc{
		{
			name:       "off always calls next",
			mode:       ModeOff,
			principal:  nil,
			mapped:     false,
			wantCode:   200,
			wantCalled: true,
		},
		{
			name:       "enforce public bypass calls next",
			mode:       ModeEnforce,
			public:     true,
			principal:  nil,
			mapped:     false,
			wantCode:   200,
			wantCalled: true,
		},
		{
			name:       "shadow unmapped never denies",
			mode:       ModeShadow,
			principal:  &Principal{ID: "u", Roles: []string{"admin"}},
			mapped:     false,
			wantCode:   200,
			wantCalled: true,
		},
		{
			name:       "enforce unmapped denies by default",
			mode:       ModeEnforce,
			principal:  &Principal{ID: "u", Roles: []string{"admin"}},
			mapped:     false,
			wantCode:   403,
			wantReason: ReasonUnmappedRoute,
			wantCalled: false,
		},
		{
			name:       "enforce missing principal + require authn => 401",
			mode:       ModeEnforce,
			requireN:   true,
			principal:  nil,
			mapped:     true,
			wantCode:   401,
			wantReason: ReasonNoPrincipal,
			wantCalled: false,
		},
		{
			name:       "shadow missing principal + require authn => 401",
			mode:       ModeShadow,
			requireN:   true,
			principal:  nil,
			mapped:     true,
			wantCode:   401,
			wantReason: ReasonNoPrincipal,
			wantCalled: false,
		},
		{
			name:       "shadow policy deny never denies",
			mode:       ModeShadow,
			principal:  &Principal{ID: "u", Roles: []string{"admin"}},
			mapped:     true,
			authzAllow: false,
			wantCode:   200,
			wantCalled: true,
		},
		{
			name:       "enforce policy allow calls next",
			mode:       ModeEnforce,
			principal:  &Principal{ID: "u", Roles: []string{"admin"}},
			mapped:     true,
			authzAllow: true,
			wantCode:   200,
			wantCalled: true,
		},
		{
			name:       "enforce policy deny => 403",
			mode:       ModeEnforce,
			principal:  &Principal{ID: "u", Roles: []string{"admin"}},
			mapped:     true,
			authzAllow: false,
			wantCode:   403,
			wantReason: ReasonPolicyDenied,
			wantCalled: false,
		},
		{
			name:       "bad request mapping => 400",
			mode:       ModeEnforce,
			principal:  &Principal{ID: "u", Roles: []string{"admin"}},
			mapped:     false,
			mapErr:     NewBadRequestError("bad path"),
			wantCode:   400,
			wantReason: ReasonBadRequest,
			wantCalled: false,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			a := newTestAuthorizerMW(t, c.authzAllow)

			prefix := "/public"
			path := "/protected"
			if c.public {
				path = prefix + "/ping"
			}

			mw := NewMiddleware(a, testMapper{rd: RouteDecision{Mapped: c.mapped, Object: "obj", Action: "act"}, err: c.mapErr},
				WithMode(c.mode),
				WithRequireAuthn(c.requireN),
				WithPublicPrefixes([]string{prefix}),
			)

			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(200)
			})

			r := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
			if c.principal != nil {
				r = r.WithContext(SetPrincipal(r.Context(), c.principal))
			}

			rr := httptest.NewRecorder()
			mw.Handler(next).ServeHTTP(rr, r)

			if rr.Code != c.wantCode {
				t.Fatalf("status: got %d want %d body=%s", rr.Code, c.wantCode, rr.Body.String())
			}
			if called != c.wantCalled {
				t.Fatalf("next called: got %v want %v", called, c.wantCalled)
			}

			if rr.Code != 200 {
				var dr DenyResponseV1
				if err := json.Unmarshal(rr.Body.Bytes(), &dr); err != nil {
					t.Fatalf("decode deny: %v", err)
				}
				if dr.SchemaVersion != DenySchemaVersionV1 {
					t.Fatalf("schema_version: got %q", dr.SchemaVersion)
				}
				if dr.Reason != c.wantReason {
					t.Fatalf("reason: got %q want %q", dr.Reason, c.wantReason)
				}
			}
		})
	}
}
