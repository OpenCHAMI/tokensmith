// SPDX-FileCopyrightText: 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package deviceauth

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/authz"
)

func TestGitLabRoleMappingConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		valid       bool
		level       int
		want        string
	}{
		{"omitted uses default", `{}`, true, 40, "admin"},
		{"null uses default", `{"gitlab_role_mapping":null}`, true, 40, "admin"},
		{"empty denies all", `{"gitlab_role_mapping":{}}`, true, 40, ""},
		{"custom role", `{"gitlab_role_mapping":{"maintainer":"viewer"}}`, true, 40, "viewer"},
		{"unlisted owner denied", `{"gitlab_role_mapping":{"maintainer":"viewer"}}`, true, 50, ""},
		{"unknown source", `{"gitlab_role_mapping":{"member":"viewer"}}`, false, 0, ""},
		{"case sensitive source", `{"gitlab_role_mapping":{"Maintainer":"viewer"}}`, false, 0, ""},
		{"unknown target", `{"gitlab_role_mapping":{"maintainer":"root"}}`, false, 0, ""},
		{"empty target", `{"gitlab_role_mapping":{"maintainer":""}}`, false, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := config()
			if err := json.Unmarshal([]byte(tc.input), &c); err != nil {
				t.Fatal(err)
			}
			err := c.Validate()
			if tc.valid {
				if err != nil || c.clusterRole(tc.level) != tc.want {
					t.Fatalf("role=%q err=%v", c.clusterRole(tc.level), err)
				}
			} else if err != ErrDenied {
				t.Fatalf("invalid mapping accepted: %v", err)
			}
		})
	}
}

func TestConfiguredGitLabRolesAreIssuedAndUnlistedRolesDenied(t *testing.T) {
	for _, tc := range []struct {
		level int
		want  string
	}{
		{40, "operator"}, {30, "viewer"}, {50, ""}, {20, ""}, {10, ""}, {0, ""}, {15, ""}, {60, ""},
	} {
		t.Run(decimal(int64(tc.level)), func(t *testing.T) {
			c := config()
			c.GitLabRoleMapping = map[string]string{"maintainer": "operator", "developer": "viewer"}
			x := setupWithConfig(t, c)
			x.f.level = tc.level
			result, err := x.login(t)
			if tc.want == "" {
				if err != ErrDenied || result.Access != "" || result.Renewal != "" {
					t.Fatal("unmapped access level received a session")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			claims, err := x.k.Verify(result.Access, config(), x.now)
			if err != nil || claims.Role != tc.want || x.audit[len(x.audit)-1].Role != tc.want {
				t.Fatalf("wrong issued/audited role: claims=%#v err=%v", claims, err)
			}
		})
	}
	for _, mapping := range []map[string]string{{}, {"guest": "viewer"}} {
		c := config()
		c.GitLabRoleMapping = mapping
		x := setupWithConfig(t, c)
		x.f.level = 10
		result, err := x.login(t)
		if len(mapping) == 0 {
			if err != ErrDenied || result.Access != "" {
				t.Fatal("explicit empty policy did not deny access")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			claims, err := x.k.Verify(result.Access, config(), x.now)
			if err != nil || claims.Role != "viewer" {
				t.Fatal("explicit guest mapping was not applied")
			}
		}
	}
}

func TestGitLabMappingSnapshotAndRenewal(t *testing.T) {
	c := config()
	c.GitLabRoleMapping = map[string]string{"maintainer": "operator", "developer": "viewer"}
	x := setupWithConfig(t, c)
	// Caller mutation after construction must not change the retained policy.
	c.GitLabRoleMapping["maintainer"] = "admin"
	delete(c.GitLabRoleMapping, "developer")
	first, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := x.k.Verify(first.Access, config(), x.now)
	if err != nil || claims.Role != "operator" {
		t.Fatal("caller mutation changed the configured role")
	}
	x.f.level = 30
	x.now = x.now.Add(90 * time.Second)
	renewed, err := x.a.Renew(ctx, first.Renewal)
	if err != nil {
		t.Fatal(err)
	}
	claims, err = x.k.Verify(renewed.Access, config(), x.now)
	if err != nil || claims.Role != "viewer" {
		t.Fatal("renewal did not apply the configured demotion")
	}
	x.f.level = 20
	x.now = x.now.Add(90 * time.Second)
	if result, err := x.a.Renew(ctx, first.Renewal); err != ErrDenied || result.Access != "" {
		t.Fatal("renewal granted an unmapped membership")
	}
}

func TestCustomGitLabMappingReachesCasbin(t *testing.T) {
	c := config()
	c.GitLabRoleMapping = map[string]string{"maintainer": "viewer"}
	x := setupWithConfig(t, c)
	x.now = time.Now().UTC().Truncate(time.Second).Add(-5 * time.Second)
	x.f.expiry = x.now.Add(time.Hour)
	result, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	authenticate, err := Middleware(c, func(string) (*rsa.PublicKey, error) { return &x.k.private.PublicKey, nil })
	if err != nil {
		t.Fatal(err)
	}
	// The middleware also retains a snapshot, even if the caller invalidates its map.
	c.GitLabRoleMapping["maintainer"] = "invalid"
	authorize := authz.NewMiddleware(deviceAuthPolicy(t), authz.PathMethodMapper{MethodToAction: authz.MethodToActionREST()}, authz.WithRequireAuthn(true))
	handled := 0
	handler := authenticate(authorize.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled++
		p, ok := authz.PrincipalFromContext(r.Context())
		if !ok || len(p.Roles) != 1 || p.Roles[0] != "viewer" {
			t.Fatal("configured role missing from principal")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	for _, tc := range []struct {
		method string
		status int
	}{{"GET", 204}, {"POST", 403}, {"DELETE", 403}} {
		request := httptest.NewRequest(tc.method, "/nodes", nil)
		request.Header.Set("Authorization", "Bearer "+result.Access)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != tc.status {
			t.Fatalf("%s status=%d want=%d", tc.method, response.Code, tc.status)
		}
	}
	if handled != 1 {
		t.Fatal("configured viewer reached a write/delete handler")
	}
}
