package deviceauth

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/authz"
)

// Verify the complete path from effective GitLab membership through session
// issuance to the consumer's Casbin decisions. Token-only cases live in
// principal_test.go so the preceding JWT-contract layer stands on its own.
func TestMembershipToCasbinAuthorization(t *testing.T) {
	x := setup(t)
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
		w.WriteHeader(http.StatusNoContent)
	})))

	for _, tc := range []struct {
		name, method, role string
		level, want        int
	}{
		{"reporter reads", "GET", "viewer", 20, 204},
		{"reporter cannot write", "POST", "viewer", 20, 403},
		{"reporter cannot delete", "DELETE", "viewer", 20, 403},
		{"developer writes", "POST", "operator", 30, 204},
		{"developer cannot delete", "DELETE", "operator", 30, 403},
		{"maintainer deletes", "DELETE", "admin", 40, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise membership -> issued role -> strict verification -> Casbin.
			x = setup(t)
			x.now = now.Add(-5 * time.Second)
			x.f.expiry = now.Add(time.Hour)
			x.f.level = tc.level
			result, err := x.login(t)
			if err != nil {
				t.Fatal(err)
			}
			mapper.calls, handled, principal = 0, 0, nil
			request := httptest.NewRequest(tc.method, "/nodes", nil)
			request.Header.Set("Authorization", "bEaReR "+result.Access)
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

}
