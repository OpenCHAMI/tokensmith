package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
)

func TestAuthzMiddleware_EnforceError_FailOpen(t *testing.T) {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = some_unknown_func(r.sub, p.sub)
`)
	enf, _ := casbin.NewEnforcer(m)
	opts := &AuthzOptions{ContextKey: string(ClaimsContextKey), FailOpen: true}
	h := AuthzMiddleware(enf, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/data1", nil)
	claims := &token.TSClaims{RegisteredClaims: token.NewClaims().RegisteredClaims}
	claims.Subject = "alice"
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, claims))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthzMiddleware_EnforceError_FailClosed(t *testing.T) {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = some_unknown_func(r.sub, p.sub)
`)
	enf, _ := casbin.NewEnforcer(m)
	opts := &AuthzOptions{ContextKey: string(ClaimsContextKey), FailOpen: false}
	h := AuthzMiddleware(enf, opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), "GET", "/data1", nil)
	claims := &token.TSClaims{RegisteredClaims: token.NewClaims().RegisteredClaims}
	claims.Subject = "alice"
	req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, claims))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
