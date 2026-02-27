package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDenyWriter_JSONSchemaV1(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/nodes", nil)

	resp := DenyResponseV1{
		Code:     DenyCodeAuthzDenied,
		Message:  "access denied",
		Decision: DecisionDeny,
		Reason:   ReasonPolicyDenied,
		Mode:     "ENFORCE",
		Principal: PrincipalSummary{
			ID:   "u-123",
			Type: "user",
			Roles: []string{
				"viewer",
			},
		},
		Input: Input{Object: "/v1/nodes", Action: "read", Domain: ""},
		Request: RequestSummary{
			Method: http.MethodGet,
			Path:   "/v1/nodes",
		},
		PolicyVersion: "deadbeef",
		RequestID:     "req-1",
	}

	if err := (DenyWriter{}).Write(w, r, http.StatusForbidden, resp); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := w.Result().Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content-type=%q", got)
	}

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
	}

	for _, k := range []string{"schema_version", "code", "message", "decision", "reason", "mode", "principal", "input", "policy_version", "request"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("missing key %q in body: %v", k, got)
		}
	}

	if got["schema_version"] != "authz.deny.v1" {
		t.Fatalf("schema_version=%v", got["schema_version"])
	}
}

func TestDenyWriter_HeadSuppressesBody(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodHead, "/protected", nil)

	resp := DenyResponseV1{
		Code:          DenyCodeAuthzDenied,
		Message:       "access denied",
		Decision:      DecisionDeny,
		Reason:        ReasonPolicyDenied,
		Mode:          "ENFORCE",
		Principal:     PrincipalSummary{ID: "", Type: "unknown"},
		Input:         Input{Object: "", Action: "", Domain: ""},
		PolicyVersion: "",
		Request:       RequestSummary{Method: http.MethodHead, Path: "/protected"},
	}

	if err := (DenyWriter{}).Write(w, r, http.StatusForbidden, resp); err != nil {
		t.Fatalf("write: %v", err)
	}

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d", w.Code)
	}
	if got := w.Result().Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content-type=%q", got)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body for HEAD, got %q", w.Body.String())
	}
}
