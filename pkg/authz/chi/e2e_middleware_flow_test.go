// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
//
// SPDX-License-Identifier: MIT

package chi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openchami/tokensmith/pkg/authz"
	authzchi "github.com/openchami/tokensmith/pkg/authz/chi"
	"github.com/openchami/tokensmith/pkg/authz/policyloader"
	"github.com/openchami/tokensmith/pkg/testutil"
)

type countingMetrics struct {
	decisions []struct {
		d authz.Decision
		o string
		a string
		m string
		p string
	}
}

func (m *countingMetrics) IncAuthzDecision(d authz.Decision, object, action, mode, policyVersion string) {
	m.decisions = append(m.decisions, struct {
		d authz.Decision
		o string
		a string
		m string
		p string
	}{d: d, o: object, a: action, m: mode, p: policyVersion})
}
func (m *countingMetrics) IncAuthzError(stage, mode, policyVersion string) {}

func TestE2E_ShadowMode_DeniedAllowedButMetric(t *testing.T) {
	l := policyloader.New()
	e, err := l.Load("")
	if err != nil {
		t.Fatal(err)
	}
	a, err := authz.NewAuthorizer(e, l.PolicyVersion())
	if err != nil {
		t.Fatal(err)
	}

	metrics := &countingMetrics{}
	r := testutil.AuthzTestRouter(a, authz.ModeShadow, authzchi.WithMetrics(metrics))
	r.Use(testutil.PrincipalMiddleware(func(r *http.Request) *authz.Principal {
		return &authz.Principal{ID: "u1", Roles: []string{"viewer"}}
	}))

	r.With(authzchi.Require("boot:configs", "delete")).Delete("/boot/configs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/boot/configs", nil)
	r.ServeHTTP(rr, req)

	// Shadow mode always allows but the middleware returns 200 for denied paths.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(metrics.decisions) != 1 {
		t.Fatalf("expected 1 decision metric, got %d", len(metrics.decisions))
	}
	if metrics.decisions[0].d == authz.DecisionAllow {
		t.Fatalf("expected non-allow decision in shadow mode, got %s", metrics.decisions[0].d)
	}
}

func TestE2E_EnforceMode_Denied403WithStandardBody(t *testing.T) {
	l := policyloader.New()
	e, err := l.Load("")
	if err != nil {
		t.Fatal(err)
	}
	a, err := authz.NewAuthorizer(e, l.PolicyVersion())
	if err != nil {
		t.Fatal(err)
	}

	r := testutil.AuthzTestRouter(a, authz.ModeEnforce)
	r.Use(testutil.PrincipalMiddleware(func(r *http.Request) *authz.Principal {
		return &authz.Principal{ID: "u1", Roles: []string{"viewer"}}
	}))

	r.With(authzchi.Require("boot:configs", "delete")).Delete("/boot/configs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/boot/configs", nil)
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	var body authz.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid json: %v body=%s", err, rr.Body.String())
	}
	if body.Code == "" || body.Message == "" || body.PolicyVersion == "" || body.Decision == "" {
		t.Fatalf("expected required fields, got %#v", body)
	}
	if body.PolicyVersion != l.PolicyVersion() {
		t.Fatalf("expected policy version %q, got %q", l.PolicyVersion(), body.PolicyVersion)
	}
}

func TestE2E_PolicyLoadFailure_FailFast(t *testing.T) {
	l := policyloader.New()
	_, err := l.Load("/this/dir/does/not/exist")
	if err == nil {
		t.Fatal("expected error")
	}
}
