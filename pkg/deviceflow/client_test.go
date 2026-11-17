package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Each fixture spells out its provider's wire contract independently of the
// constructor. These are local protocol tests, not real-account acceptance.
func TestProviderGrantContracts(t *testing.T) {
	entra, err := Entra("tenant-id", "application", "openid profile offline_access")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                                       string
		profile                                    Config
		deviceEndpoint, tokenEndpoint, approvalURI string
		deviceLifetime                             int
		googleAlias, noRefresh                     bool
		errorStatus                                int
	}{
		{"gitlab", GitLab("https://gitlab.example", "application"), "https://gitlab.example/oauth/authorize_device", "https://gitlab.example/oauth/token", "https://gitlab.example/oauth/device", 300, false, false, 400},
		{"github", GitHub("application", "read:user"), "https://github.com/login/device/code", "https://github.com/login/oauth/access_token", "https://github.com/login/device", 900, false, true, 200},
		{"entra", entra, "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/devicecode", "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token", "https://microsoft.com/devicelogin", 900, false, false, 400},
		{"google", Google("application", "openid profile"), "https://oauth2.googleapis.com/device/code", "https://oauth2.googleapis.com/token", "https://www.google.com/device", 1800, true, false, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.profile.DeviceEndpoint != tc.deviceEndpoint || tc.profile.TokenEndpoint != tc.tokenEndpoint || tc.profile.VerificationURI != tc.approvalURI {
				t.Fatal("profile differs from documented endpoints")
			}
			deviceURL, _ := url.Parse(tc.deviceEndpoint)
			tokenURL, _ := url.Parse(tc.tokenEndpoint)
			polls, refreshes := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Accept") != "application/json" {
					t.Error("grant must be a JSON-negotiated POST without query credentials")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				if r.PostForm.Get("client_id") != "application" {
					t.Error("missing configured client ID")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case deviceURL.Path:
					if r.PostForm.Get("scope") != tc.profile.Scope {
						t.Error("wrong scope")
					}
					prompt := map[string]any{"device_code": "private-code", "user_code": "PUBLIC-CODE", "expires_in": tc.deviceLifetime, "interval": 5}
					field := "verification_uri"
					if tc.googleAlias {
						field = "verification_url"
					}
					prompt[field] = tc.approvalURI
					_ = json.NewEncoder(w).Encode(prompt)
				case tokenURL.Path:
					if tc.name == "google" && r.PostForm.Get("client_secret") != "private-client-secret" {
						t.Error("missing privately provisioned secret")
					}
					if r.PostForm.Get("grant_type") == "refresh_token" {
						refreshes++
						if r.PostForm.Get("refresh_token") != "refresh-one" {
							t.Error("wrong refresh credential")
						}
						_ = json.NewEncoder(w).Encode(Token{Access: "access-two", Refresh: "refresh-two", Type: "Bearer", Expires: 3600})
						return
					}
					if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.PostForm.Get("device_code") != "private-code" {
						t.Error("wrong device grant")
					}
					polls++
					if polls <= 2 {
						w.WriteHeader(tc.errorStatus)
						code := "authorization_pending"
						if polls == 2 {
							code = "slow_down"
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
						return
					}
					result := Token{Access: "access-one", Refresh: "refresh-one", Type: "bearer", Expires: 3600, Scope: tc.profile.Scope}
					if tc.noRefresh {
						result.Refresh = ""
						result.Expires = 0
					}
					if tc.name == "entra" {
						result.IDToken = "unverified-id-token"
					}
					_ = json.NewEncoder(w).Encode(result)
				default:
					t.Error("unexpected endpoint", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			profile := tc.profile
			profile.DeviceEndpoint = server.URL + deviceURL.Path
			profile.TokenEndpoint = server.URL + tokenURL.Path
			if tc.name == "google" {
				profile.ClientSecret = "private-client-secret"
			}
			client, err := NewWithTransport(profile, server.Client().Transport)
			if err != nil {
				t.Fatal(err)
			}
			client.http.Transport = server.Client().Transport
			device, err := client.Start(context.Background())
			if err != nil || device.URI != tc.approvalURI || device.Expires != int64(tc.deviceLifetime) {
				t.Fatalf("invalid device prompt: %v", err)
			}
			for _, expected := range []string{"authorization_pending", "slow_down"} {
				token, err := client.Poll(context.Background(), device.Code)
				if err != nil || token.Error != expected {
					t.Fatalf("expected %s, got %v", expected, err)
				}
			}
			token, err := client.Poll(context.Background(), device.Code)
			if err != nil || token.Access != "access-one" {
				t.Fatalf("grant failed: %v", err)
			}
			if tc.noRefresh {
				if token.Refresh != "" || token.Expires != 0 {
					t.Fatal("invented missing expiry/refresh")
				}
				if _, err := client.Refresh(context.Background(), token.Refresh); err == nil {
					t.Fatal("empty refresh accepted")
				}
			} else {
				next, err := client.Refresh(context.Background(), token.Refresh)
				if err != nil || next.Refresh != "refresh-two" || refreshes != 1 {
					t.Fatalf("refresh failed: %v", err)
				}
			}
		})
	}
}

func TestGrantErrorsAndResponseBounds(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		expected   error
	}{
		{"denied", `{"error":"access_denied"}`, 400, ErrDenied},
		{"entra declined", `{"error":"authorization_declined"}`, 400, ErrDenied},
		{"expired", `{"error":"expired_token"}`, 400, ErrExpired},
		{"invalid device", `{"error":"bad_verification_code"}`, 400, ErrProtocol},
		{"outage", `{"error":"private-server-detail"}`, 503, ErrProtocol},
		{"malformed", `{`, 200, ErrProtocol},
		{"two documents", `{} {}`, 200, ErrProtocol},
		{"oversized", strings.Repeat(" ", 65537), 200, ErrProtocol},
		{"missing access", `{"token_type":"Bearer"}`, 200, ErrProtocol},
		{"wrong token type", `{"access_token":"secret","token_type":"Basic"}`, 200, ErrProtocol},
		{"error with credential", `{"error":"slow_down","access_token":"secret"}`, 400, ErrProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := New(Config{ClientID: "application", DeviceEndpoint: server.URL, TokenEndpoint: server.URL, VerificationURI: "https://approval.example/device"})
			if err != nil {
				t.Fatal(err)
			}
			client.http.Transport = server.Client().Transport
			_, err = client.Poll(context.Background(), "private-code")
			if !errors.Is(err, tc.expected) {
				t.Fatalf("got %v, want %v", err, tc.expected)
			}
		})
	}
}

func TestNoRedirectsCancellationAndTLSVerification(t *testing.T) {
	leaks := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks++; w.WriteHeader(200) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client, err := New(Config{ClientID: "application", DeviceEndpoint: server.URL, TokenEndpoint: server.URL, VerificationURI: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	// The local certificate is not in the default trust store.
	if _, err = client.Poll(context.Background(), "secret"); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	client.http.Transport = server.Client().Transport
	if _, err = client.Poll(context.Background(), "secret"); err == nil || leaks != 0 {
		t.Fatal("followed redirect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.Poll(ctx, "secret"); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestRejectUntrustedConfigurationAndApprovalURI(t *testing.T) {
	for _, endpoint := range []string{"http://provider.example", "https://user:secret@provider.example", "https://provider.example?token=secret", "https://provider.example/#fragment"} {
		if _, err := New(Config{ClientID: "app", DeviceEndpoint: endpoint, TokenEndpoint: endpoint, VerificationURI: endpoint}); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
	for _, tenant := range []string{"", "../other", "other?query", "%2fother"} {
		if _, err := Entra(tenant, "app", "openid"); err == nil {
			t.Fatal("unsafe tenant accepted")
		}
	}
	for _, prompt := range []string{
		`{"device_code":"secret","user_code":"CODE","verification_uri":"https://attacker.example","expires_in":300}`,
		`{"device_code":"secret","user_code":"CODE","verification_uri":"https://approval.example","verification_url":"https://attacker.example","expires_in":300}`,
		`{"device_code":"secret","user_code":"CODE","verification_uri":"https://approval.example","expires_in":999999}`,
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(prompt)) }))
		client, err := New(Config{ClientID: "app", DeviceEndpoint: server.URL, TokenEndpoint: server.URL, VerificationURI: "https://approval.example"})
		if err != nil {
			t.Fatal(err)
		}
		client.http.Transport = server.Client().Transport
		_, err = client.Start(context.Background())
		server.Close()
		if err == nil {
			t.Fatal("unsafe approval prompt accepted")
		}
	}
}
