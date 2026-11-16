package deviceauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGitLabHTTPSIdentityAndInheritedMembership(t *testing.T) {
	for _, mode := range []string{"inherited-developer", "old-valid", "wrong-app", "wrong-user", "expired", "future", "wrong-scope", "identity-outage", "membership-outage", "nonmember", "redirect", "malformed", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Unix(1800000000, 0)
			members := 0
			leaked := false
			var origin string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				send := func(v any) { _ = json.NewEncoder(w).Encode(v) }
				switch r.URL.Path {
				case "/oauth/token/info":
					if r.Header.Get("Authorization") != "Bearer user-secret" {
						t.Error("identity credential missing")
					}
					if mode == "identity-outage" {
						w.WriteHeader(503)
						send(map[string]string{"error": "private error user-secret"})
						return
					}
					if mode == "redirect" {
						http.Redirect(w, r, origin+"/steal", http.StatusFound)
						return
					}
					if mode == "malformed" {
						_, _ = w.Write([]byte(`{"application":`))
						return
					}
					uid := "application"
					if mode == "wrong-app" {
						uid = "attacker-app"
					}
					owner := int64(207)
					if mode == "wrong-user" {
						owner = 208
					}
					created := now.Unix() - 100
					if mode == "expired" {
						created -= 7200
					}
					if mode == "old-valid" {
						created -= 7000
					}
					remaining := int64(7200)
					if mode == "old-valid" {
						remaining = 100
					}
					if mode == "expired" {
						remaining = 0
					}
					if mode == "future" {
						created = now.Unix() + 1
					}
					scope := []string{"read_user"}
					if mode == "wrong-scope" {
						scope = []string{"read_api"}
					}
					send(map[string]any{"application": map[string]any{"uid": uid}, "resource_owner_id": owner, "scope": scope, "created_at": created, "expires_in": remaining})
				case "/api/v4/user":
					state := "active"
					if mode == "blocked" {
						state = "blocked"
					}
					send(map[string]any{"id": 207, "state": state})
				case "/api/v4/projects/701/members/all/207":
					members++
					if r.Header.Get("Authorization") != "Bearer verifier-secret" {
						t.Error("membership must use verifier credential")
					}
					if mode == "membership-outage" {
						w.WriteHeader(503)
						send(map[string]string{"error": "unavailable"})
						return
					}
					if mode == "nonmember" {
						w.WriteHeader(404)
						send(map[string]string{"error": "not found"})
						return
					}
					send(map[string]any{"id": 207, "access_level": 30})
				case "/api/v4/projects/701/members/207":
					t.Error("direct membership lookup excludes inheritance")
					w.WriteHeader(404)
				case "/steal":
					leaked = true
					w.WriteHeader(401)
				default:
					t.Error("unconfigured GitLab endpoint", r.URL.Path)
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
			id, err := g.Verify(context.Background(), "user-secret", now)
			identityOK := mode == "inherited-developer" || mode == "old-valid" || mode == "membership-outage" || mode == "nonmember"
			if !identityOK {
				if err == nil {
					t.Fatal("unverified identity accepted")
				}
				if members != 0 || leaked {
					t.Fatal("continued after identity rejection/redirect")
				}
				return
			}
			if err != nil || id.UserID != 207 {
				t.Fatal("valid identity rejected", err)
			}
			if mode == "old-valid" && !id.ExpiresAt.Equal(now.Add(99*time.Second)) {
				t.Fatal("token-info remaining lifetime treated as original TTL")
			}
			level, err := g.Membership(context.Background(), id.UserID)
			if mode == "inherited-developer" || mode == "old-valid" {
				if err != nil || level != 30 {
					t.Fatal("effective inherited developer rejected")
				}
			} else if err == nil {
				t.Fatal("membership failure accepted")
			}
		})
	}
}
func TestGitLabDeviceRefreshRevokeWire(t *testing.T) {
	for _, mode := range []string{"success", "pending", "slow_down", "access_denied", "expired_token", "invalid_grant", "bad_scope", "id-token", "redirect-uri"} {
		t.Run(mode, func(t *testing.T) {
			var origin string
			seenRefresh, seenRevoke := false, false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				if r.Form.Get("client_id") != "application" {
					t.Error("wrong app")
				}
				if strings.Contains(r.URL.RawQuery, "secret") {
					t.Error("secret in query")
				}
				switch r.URL.Path {
				case "/oauth/authorize_device":
					if r.Form.Get("scope") != "read_user" {
						t.Error("excess device-authorization scope")
					}
					uri := origin + "/oauth/device"
					if mode == "redirect-uri" {
						uri = "https://evil.example/oauth/device"
					}
					_ = json.NewEncoder(w).Encode(Device{Code: "device-secret", UserCode: "user-code", URI: uri, Expires: 300, Interval: 5})
				case "/oauth/token":
					if r.Form.Get("grant_type") == "refresh_token" {
						seenRefresh = true
						if r.Form.Get("refresh_token") != "refresh-secret" {
							t.Error("wrong refresh credential")
						}
					} else if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "device-secret" {
						t.Error("unsupported grant")
					}
					switch mode {
					case "pending", "slow_down", "access_denied", "expired_token", "invalid_grant":
						value := mode
						if mode == "pending" {
							value = "authorization_pending"
						}
						w.WriteHeader(400)
						_ = json.NewEncoder(w).Encode(map[string]string{"error": value})
						return
					}
					c := Credential{Access: "user-secret", Refresh: "refresh-secret", Type: "bearer", Scope: "read_user", Expires: 7200}
					if mode == "bad_scope" {
						c.Scope = "read_api"
					}
					if mode == "id-token" {
						c.Access = ""
					}
					_ = json.NewEncoder(w).Encode(c)
				case "/oauth/revoke":
					seenRevoke = true
					if r.Form.Get("token") != "user-secret" {
						t.Error("wrong revocation token")
					}
					w.WriteHeader(200)
				default:
					t.Error("unexpected endpoint")
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
			d, err := g.Start(ctx)
			if mode == "redirect-uri" {
				if err == nil {
					t.Fatal("untrusted approval link")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			credential, err := g.Poll(ctx, d.Code)
			if mode == "pending" || mode == "slow_down" {
				if err != nil || credential.Error == "" {
					t.Fatal("retryable protocol error discarded")
				}
				return
			}
			if mode != "success" {
				if err == nil {
					t.Fatal("invalid grant accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = g.Refresh(ctx, credential.Refresh); err != nil || !seenRefresh {
				t.Fatal("refresh not exercised")
			}
			if err = g.Revoke(ctx, credential.Access); err != nil || !seenRevoke {
				t.Fatal("revoke not exercised")
			}
		})
	}
}
func TestConfigBudgetAndFixedAuthority(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"cleartext origin", func(c *Config) { c.Issuer = "http://gitlab.example" }},
		{"origin with path", func(c *Config) { c.Issuer = "https://gitlab.example/path" }},
		{"origin with credentials", func(c *Config) { c.Issuer = "https://user:secret@gitlab.example" }},
		{"missing project", func(c *Config) { c.ProjectID = 0 }},
		{"membership cache too long", func(c *Config) { c.CacheSeconds = 91 }},
		{"token lifetime too long", func(c *Config) { c.TokenSeconds = 181 }},
		{"clock budget too large", func(c *Config) { c.SkewSeconds = 31 }},
		{"extended session", func(c *Config) { c.AbsoluteSeconds = 36001 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config()
			tc.change(&c)
			if _, err := NewGitLab(c, "secret"); err == nil {
				t.Fatal("invalid authority config accepted")
			}
		})
	}
}
