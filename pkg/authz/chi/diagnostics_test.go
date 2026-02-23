package chi_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	chimid "github.com/openchami/tokensmith/pkg/authz/chi"
)

func TestDiagnosticsHandler(t *testing.T) {
	h := chimid.DiagnosticsHandler("enforce", "deadbeef", chimid.PolicySourceBaselineFragments)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example/diag", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}

	var got chimid.Diagnostics
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Mode != "enforce" {
		t.Fatalf("mode=%q", got.Mode)
	}
	if got.PolicyVersion != "deadbeef" {
		t.Fatalf("policy_version=%q", got.PolicyVersion)
	}
	if got.PolicySource != chimid.PolicySourceBaselineFragments {
		t.Fatalf("policy_source=%q", got.PolicySource)
	}
}
