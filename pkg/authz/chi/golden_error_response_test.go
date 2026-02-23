package chi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openchami/tokensmith/pkg/authz"
	authzchi "github.com/openchami/tokensmith/pkg/authz/chi"
	"github.com/openchami/tokensmith/pkg/authz/policyloader"
)

func TestGoldenErrorResponseSchema(t *testing.T) {
	l := policyloader.New()
	e, err := l.Load("")
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	a, err := authz.NewAuthorizer(e, l.PolicyVersion())
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}

	m := authzchi.New(a, authzchi.WithMode(authz.ModeEnforce), authzchi.WithAllowMissingPrincipal(true))

	r := chi.NewRouter()
	r.Use(m.Handler)
	r.With(authzchi.Require("boot:configs", "delete")).Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Missing principal but allowMissingPrincipal=true => enforced denial with
	// stable JSON body.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	// Golden schema: required keys exist.
	for _, k := range []string{"code", "message", "policy_version", "decision"} {
		if _, ok := body[k]; !ok {
			t.Fatalf("missing key %q in body: %v", k, body)
		}
	}
}
