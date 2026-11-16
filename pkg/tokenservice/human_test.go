package tokenservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openchami/tokensmith/pkg/deviceauth"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/rs/zerolog"
)

func deviceAuthServiceFixture(t *testing.T) (*TokenService, *deviceauth.Config) {
	t.Helper()
	manager := keys.NewKeyManager()
	if err := manager.GenerateRSAKeyPair(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	service, err := NewTokenService(manager, Config{
		Issuer:                    "https://cluster.example",
		RFC8693BootstrapStorePath: filepath.Join(dir, "bootstrap"),
		RFC8693RefreshStorePath:   filepath.Join(dir, "refresh"),
	})
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "verifier")
	if err := os.WriteFile(secret, []byte("synthetic-verifier"), 0600); err != nil {
		t.Fatal(err)
	}
	return service, &deviceauth.Config{
		Issuer: "https://gitlab.example", ClientID: "application", ProjectID: 701,
		ClusterIssuer: "https://cluster.example", Audience: "openchami-device-auth", VerifierFile: secret,
		CacheSeconds: 90, TokenSeconds: 180, SkewSeconds: 30, AbsoluteSeconds: 36000,
	}
}

func TestDeviceAuthOptInPreservesExistingJWKSAndRoutes(t *testing.T) {
	service, config := deviceAuthServiceFixture(t)
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		service.newRouter(zerolog.Nop()).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		return response
	}
	if err := service.ConfigureDeviceAuth(nil); err != nil {
		t.Fatal(err)
	}
	if response := get("/device-auth/start"); response.Code != http.StatusNotFound {
		t.Fatal("device-authorization endpoint enabled without configuration")
	}
	before := get("/.well-known/jwks.json")
	if err := service.ConfigureDeviceAuth(config); err != nil {
		t.Fatal(err)
	}
	after := get("/.well-known/jwks.json")
	if before.Code != 200 || after.Code != 200 || before.Body.String() != after.Body.String() {
		t.Fatal("device-authorization opt-in changed existing JWKS")
	}
	for _, path := range []string{"/health", "/oauth/token", "/token", "/oauth/exchange", "/oauth/revoke", "/service-identity/session"} {
		response := get(path)
		if response.Code == http.StatusNotFound {
			t.Fatalf("existing route disappeared: %s", path)
		}
	}
	if response := get("/device-auth/start"); response.Code != http.StatusMethodNotAllowed {
		t.Fatal("device-authorization route missing or accepts GET")
	}
	if err := service.ConfigureDeviceAuth(config); err == nil {
		t.Fatal("live policy reconfiguration accepted")
	}
}

func TestDeviceAuthRoutesRejectCallerAuthorityWithoutCredentialLogging(t *testing.T) {
	service, config := deviceAuthServiceFixture(t)
	if err := service.ConfigureDeviceAuth(config); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	handler := service.newRouter(zerolog.New(&logs))
	for _, path := range []string{"/device-auth/start", "/device-auth/poll", "/device-auth/renew", "/device-auth/logout"} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"role":"admin","user_id":207}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("caller authority accepted at %s: %d", path, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/device-auth/start?token=SENSITIVE-QUERY", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "SENSITIVE-AGENT")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatal("query credential accepted")
	}
	if strings.Contains(logs.String(), "SENSITIVE-") {
		t.Fatal("device-authorization request metadata reached legacy logger")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential response is cacheable")
	}
}

func TestDeviceAuthConfigurationRejectsUnsafeSecretsAndSigningPolicy(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *TokenService, *deviceauth.Config)
	}{
		{"wrong issuer", func(t *testing.T, s *TokenService, c *deviceauth.Config) { c.ClusterIssuer = "https://other.example" }},
		{"world readable", func(t *testing.T, s *TokenService, c *deviceauth.Config) {
			if err := os.Chmod(c.VerifierFile, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing secret", func(t *testing.T, s *TokenService, c *deviceauth.Config) {
			c.VerifierFile = filepath.Join(t.TempDir(), "missing")
		}},
		{"empty secret", func(t *testing.T, s *TokenService, c *deviceauth.Config) {
			if err := os.WriteFile(c.VerifierFile, []byte(" \n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized secret", func(t *testing.T, s *TokenService, c *deviceauth.Config) {
			if err := os.WriteFile(c.VerifierFile, bytes.Repeat([]byte("x"), 16385), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"different algorithm", func(t *testing.T, s *TokenService, c *deviceauth.Config) {
			if err := s.TokenManager.SetSigningAlgorithm("RS256"); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service, config := deviceAuthServiceFixture(t)
			tc.change(t, service, config)
			if err := service.ConfigureDeviceAuth(config); err == nil {
				t.Fatal("unsafe device-authorization configuration accepted")
			}
			if service.deviceAuth != nil {
				t.Fatal("failed configuration partially enabled authority")
			}
		})
	}
}

func TestDeviceAuthFileConfigRoundTrip(t *testing.T) {
	_, config := deviceAuthServiceFixture(t)
	path := filepath.Join(t.TempDir(), "tokensmith.json")
	data, err := json.Marshal(FileConfig{DeviceAuth: config})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["device_auth"]; !ok {
		t.Fatal("device_auth configuration key missing from serialized policy")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFileConfig(path)
	if err != nil || loaded.DeviceAuth == nil || *loaded.DeviceAuth != *config {
		t.Fatalf("device-authorization policy did not survive config loading: %v", err)
	}
}
