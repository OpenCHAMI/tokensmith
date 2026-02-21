package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAuthzMiddleware_DeniesWhenNoClaims(t *testing.T) {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	enf, _ := casbin.NewEnforcer(m)
	opts := &AuthzOptions{ContextKey: string(ClaimsContextKey)}
	h := AuthzMiddleware(enf, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/data1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthzMiddleware_ExemptPath(t *testing.T) {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	enf, _ := casbin.NewEnforcer(m)
	opts := &AuthzOptions{ContextKey: string(ClaimsContextKey), ExemptPaths: []string{"/public*"}}
	h := AuthzMiddleware(enf, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/public/info", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthzMiddleware_DeniedIncrementsMetric(t *testing.T) {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	enf, _ := casbin.NewEnforcer(m)
	opts := &AuthzOptions{ContextKey: string(ClaimsContextKey)}
	h := AuthzMiddleware(enf, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/data1", nil)
	// add claims that map to a subject that won't be allowed
	claims := &token.TSClaims{RegisteredClaims: token.NewClaims().RegisteredClaims}
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, claims))
	w := httptest.NewRecorder()

	start := testutil.ToFloat64(authzDeniedCounter)
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	c := testutil.ToFloat64(authzDeniedCounter)
	assert.Equal(t, start+1, c)
}

func TestAuthzMiddleware_AllowsWhenAllowed(t *testing.T) {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	enf, _ := casbin.NewEnforcer(m)
	// add a policy for user:alice to access /data1 with get
	ok, err := enf.AddPolicy("user:alice", "/data1", "get")
	assert.NoError(t, err)
	assert.True(t, ok)
	opts := &AuthzOptions{ContextKey: string(ClaimsContextKey)}
	h := AuthzMiddleware(enf, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/data1", nil)
	// add claims that map to user:alice
	claims := &token.TSClaims{RegisteredClaims: token.NewClaims().RegisteredClaims}
	claims.Subject = "alice"
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, claims))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}
