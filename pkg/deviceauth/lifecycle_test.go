package deviceauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Exercise the HTTP broker, real GitLab adapter and real signer together.
func TestBrokerHTTPRealOAuthLifecycle(t *testing.T) {
	now := time.Unix(1800000000, 0)
	issued := now
	level := 40
	outage := false
	refreshes := 0
	revoked := false
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		send := func(v any) { _ = json.NewEncoder(w).Encode(v) }
		if outage {
			w.WriteHeader(503)
			send(map[string]string{"error": "sensitive upstream failure"})
			return
		}
		switch r.URL.Path {
		case "/oauth/authorize_device":
			send(Device{Code: "device-secret", UserCode: "user-code", URI: origin + "/oauth/device", Expires: 300, Interval: 5})
		case "/oauth/token":
			now = now.Add(2 * time.Second)
			issued = now
			if r.Form.Get("grant_type") == "refresh_token" {
				refreshes++
				issued = now
			}
			send(Credential{Access: "access-secret", Refresh: "refresh-secret", Type: "Bearer", Scope: "read_user", Expires: 7200})
		case "/oauth/token/info":
			send(map[string]any{"application": map[string]string{"uid": "application"}, "resource_owner_id": 207, "scope": []string{"read_user"}, "created_at": issued.Unix(), "expires_in": 7200 - int64(now.Sub(issued).Seconds())})
		case "/api/v4/user":
			send(map[string]any{"id": 207, "state": "active"})
		case "/api/v4/projects/701/members/all/207":
			if r.Header.Get("Authorization") != "Bearer verifier-secret" {
				t.Error("wrong membership credential")
			}
			send(map[string]int{"id": 207, "access_level": level})
		case "/oauth/revoke":
			revoked = true
			w.WriteHeader(200)
		default:
			t.Error("unexpected endpoint", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	origin = server.URL
	c := config()
	c.Issuer = origin
	g, err := NewGitLab(c, "verifier-secret")
	if err != nil {
		t.Fatal(err)
	}
	g.client.Transport = server.Client().Transport
	fixture := setup(t)
	a, err := New(c, g, fixture.k, func(Audit) {})
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return now }
	broker := httptest.NewServer(a)
	defer broker.Close()
	call := func(path, body, bearer string, status int) []byte {
		t.Helper()
		req, err := http.NewRequest("POST", broker.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := broker.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != status {
			t.Fatalf("broker status %d want %d", resp.StatusCode, status)
		}
		return b
	}
	login := func() Result {
		t.Helper()
		var d DeviceResponse
		_ = json.Unmarshal(call("/device-auth/start", `{}`, "", 200), &d)
		now = now.Add(5 * time.Second)
		var r Result
		_ = json.Unmarshal(call("/device-auth/poll", `{"transaction":"`+d.Transaction+`"}`, "", 200), &r)
		if r.Renewal == "" {
			t.Fatal("missing session")
		}
		call("/device-auth/poll", `{"transaction":"`+d.Transaction+`"}`, "", 401)
		return r
	}
	r := login()
	deadline := r.Deadline
	claims, err := fixture.k.Verify(r.Access, c, now)
	if err != nil || claims.Role != "admin" {
		t.Fatal("admin positive control failed")
	}
	level = 20
	now = now.Add(7100 * time.Second)
	var next Result
	_ = json.Unmarshal(call("/device-auth/renew", `{}`, r.Renewal, 200), &next)
	claims, err = fixture.k.Verify(next.Access, c, now)
	if err != nil || claims.Role != "viewer" || claims.UserID != 207 || next.Deadline != deadline || refreshes != 1 {
		t.Fatal("renewal contract failed")
	}
	outage = true
	call("/device-auth/renew", `{}`, r.Renewal, 401)
	if _, err = fixture.k.Verify(next.Access, c, now); err != nil {
		t.Fatal("outage invalidated unexpired token")
	}
	outage = false
	call("/device-auth/renew", `{}`, r.Renewal, 401)
	r = login()
	call("/device-auth/logout", `{}`, r.Renewal, 200)
	call("/device-auth/renew", `{}`, r.Renewal, 401)
	if !revoked {
		t.Fatal("logout did not revoke upstream authorization")
	}
}
