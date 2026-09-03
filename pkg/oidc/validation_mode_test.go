// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// modeProvider is a fake OIDC provider that counts how often each endpoint is
// used, so tests can assert which validation path actually ran.
type modeProvider struct {
	server         *httptest.Server
	key            *rsa.PrivateKey
	kid            string
	introspections int64
	jwksFetches    int64
	jwksDown       atomic.Bool
	introspectDown atomic.Bool
	introspectBody map[string]interface{}
}

func newModeProvider(t *testing.T) *modeProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	mp := &modeProvider{key: key, kid: "sig-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                 base,
			"introspection_endpoint": base + "/introspect",
			"jwks_uri":               base + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&mp.jwksFetches, 1)
		if mp.jwksDown.Load() {
			http.Error(w, "jwks unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{ // an encryption key must never verify a token
					"kty": "RSA", "use": "enc", "alg": "RSA-OAEP", "kid": "enc-key",
					"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				},
				{
					"kty": "RSA", "use": "sig", "alg": "RS256", "kid": mp.kid,
					"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				},
			},
		})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&mp.introspections, 1)
		if mp.introspectDown.Load() {
			http.Error(w, "introspection unavailable", http.StatusServiceUnavailable)
			return
		}
		body := mp.introspectBody
		if body == nil {
			body = map[string]interface{}{
				"active": true, "username": "via-introspection",
				"iss": mp.server.URL, "aud": "client",
				"exp": float64(time.Now().Add(time.Hour).Unix()),
				"iat": float64(time.Now().Unix()),
			}
		}
		_ = json.NewEncoder(w).Encode(body)
	})

	mp.server = httptest.NewServer(mux)
	t.Cleanup(mp.server.Close)
	return mp
}

func (mp *modeProvider) claims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                mp.server.URL,
		"aud":                "client",
		"sub":                "user-uuid",
		"preferred_username": "nchalla",
		"exp":                time.Now().Add(15 * time.Minute).Unix(),
		"iat":                time.Now().Unix(),
	}
}

func (mp *modeProvider) sign(t *testing.T, claims jwt.MapClaims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(mp.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func (mp *modeProvider) introspectCount() int64 { return atomic.LoadInt64(&mp.introspections) }
func (mp *modeProvider) jwksCount() int64       { return atomic.LoadInt64(&mp.jwksFetches) }

func TestParseValidationMode(t *testing.T) {
	for input, want := range map[string]ValidationMode{
		"":         ValidationModeOffline,
		"offline":  ValidationModeOffline,
		"OFFLINE":  ValidationModeOffline,
		" online ": ValidationModeOnline,
		"online":   ValidationModeOnline,
	} {
		got, err := ParseValidationMode(input)
		if err != nil {
			t.Fatalf("ParseValidationMode(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseValidationMode(%q) = %q, want %q", input, got, want)
		}
	}
	if _, err := ParseValidationMode("sometimes"); err == nil {
		t.Fatal("expected an error for an unsupported mode")
	}
}

// Offline is the default and must not touch the introspection endpoint.
func TestOfflineModeUsesJWKSOnly(t *testing.T) {
	mp := newModeProvider(t)
	p := NewSimpleProvider(mp.server.URL, "client", "secret")

	if p.ValidationMode() != ValidationModeOffline {
		t.Fatalf("default mode = %q, want offline", p.ValidationMode())
	}

	token := mp.sign(t, mp.claims(), mp.kid)
	for i := 0; i < 3; i++ {
		resp, err := p.IntrospectToken(context.Background(), token)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if resp.Username != "nchalla" {
			t.Fatalf("call %d: username = %q, want nchalla (local path)", i, resp.Username)
		}
	}
	if got := mp.introspectCount(); got != 0 {
		t.Fatalf("introspection called %d times in offline mode, want 0", got)
	}
	// The JWKS is cached: fetched once, not once per validation.
	if got := mp.jwksCount(); got != 1 {
		t.Fatalf("JWKS fetched %d times, want 1 (cached)", got)
	}
}

// Online mode must consult the provider on every call, so revocation is seen.
func TestOnlineModeUsesIntrospection(t *testing.T) {
	mp := newModeProvider(t)
	p := NewSimpleProvider(mp.server.URL, "client", "secret",
		WithValidationMode(ValidationModeOnline))

	token := mp.sign(t, mp.claims(), mp.kid)
	for i := 0; i < 3; i++ {
		resp, err := p.IntrospectToken(context.Background(), token)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if resp.Username != "via-introspection" {
			t.Fatalf("call %d: username = %q, want via-introspection", i, resp.Username)
		}
	}
	if got := mp.introspectCount(); got != 3 {
		t.Fatalf("introspection called %d times, want 3 (once per validation)", got)
	}
}

// Online mode falls back to JWKS when the endpoint is unreachable, so a provider
// outage does not take authentication down with it.
func TestOnlineModeFallsBackWhenIntrospectionUnavailable(t *testing.T) {
	mp := newModeProvider(t)
	mp.introspectDown.Store(true)
	p := NewSimpleProvider(mp.server.URL, "client", "secret",
		WithValidationMode(ValidationModeOnline))

	resp, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), mp.kid))
	if err != nil {
		t.Fatalf("expected fallback to local validation: %v", err)
	}
	if resp.Username != "nchalla" {
		t.Fatalf("username = %q, want nchalla (local fallback)", resp.Username)
	}
}

// A provider that answers and rejects the token is authoritative: falling back
// locally would override its revocation decision, which is the whole reason for
// choosing online mode.
func TestOnlineModeDoesNotFallBackOnRejection(t *testing.T) {
	mp := newModeProvider(t)
	mp.introspectBody = map[string]interface{}{"active": false}
	p := NewSimpleProvider(mp.server.URL, "client", "secret",
		WithValidationMode(ValidationModeOnline))

	resp, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), mp.kid))
	if err == nil && resp != nil && resp.Active {
		t.Fatal("a revoked token was accepted via local fallback")
	}
}

// Offline mode falls back only when the JWKS itself cannot be fetched.
func TestOfflineModeFallsBackWhenJWKSUnavailable(t *testing.T) {
	mp := newModeProvider(t)
	mp.jwksDown.Store(true)
	p := NewSimpleProvider(mp.server.URL, "client", "secret")

	resp, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), mp.kid))
	if err != nil {
		t.Fatalf("expected fallback to introspection: %v", err)
	}
	if resp.Username != "via-introspection" {
		t.Fatalf("username = %q, want via-introspection", resp.Username)
	}
	if mp.introspectCount() == 0 {
		t.Fatal("expected introspection to be used when JWKS is unavailable")
	}
}

// An unknown kid triggers exactly one JWKS refresh, so key rotation self-heals
// without waiting for the cache TTL.
func TestUnknownKeyIDTriggersJWKSRefresh(t *testing.T) {
	mp := newModeProvider(t)
	p := NewSimpleProvider(mp.server.URL, "client", "secret")

	// Prime the cache with a valid token.
	if _, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), mp.kid)); err != nil {
		t.Fatalf("priming call: %v", err)
	}
	before := mp.jwksCount()

	// Rotate: the provider now signs with a kid the cache has never seen.
	mp.kid = "sig-key-2"
	resp, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), "sig-key-2"))
	if err != nil {
		t.Fatalf("expected the refreshed JWKS to validate the rotated key: %v", err)
	}
	if resp.Username != "nchalla" {
		t.Fatalf("username = %q, want nchalla", resp.Username)
	}
	if mp.jwksCount() <= before {
		t.Fatal("expected a JWKS refresh after an unknown kid")
	}
}

// Encryption keys published alongside signing keys must never verify a token.
func TestEncryptionKeysAreNotUsedForVerification(t *testing.T) {
	mp := newModeProvider(t)
	p := NewSimpleProvider(mp.server.URL, "client", "secret")

	// Signed with the real key but claiming the encryption key's kid.
	_, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), "enc-key"))
	if err == nil {
		t.Fatal("a token claiming an encryption key's kid was accepted")
	}
}

func TestIssuerTrailingSlashTolerated(t *testing.T) {
	mp := newModeProvider(t)
	// Configured with a trailing slash; the provider issues without one.
	p := NewSimpleProvider(mp.server.URL+"/", "client", "secret")

	resp, err := p.IntrospectToken(context.Background(), mp.sign(t, mp.claims(), mp.kid))
	if err != nil {
		t.Fatalf("trailing slash on the configured issuer broke validation: %v", err)
	}
	if resp.Username != "nchalla" {
		t.Fatalf("username = %q, want nchalla", resp.Username)
	}
}

func TestECPublicKeyFromJWK(t *testing.T) {
	for _, tc := range []struct {
		name  string
		crv   string
		curve elliptic.Curve
	}{
		{"P-256", "P-256", elliptic.P256()},
		{"P-384", "P-384", elliptic.P384()},
		{"P-521", "P-521", elliptic.P521()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			got, err := publicKeyFromJWK(map[string]interface{}{
				"kty": "EC", "crv": tc.crv,
				"x": base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
				"y": base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			pub, ok := got.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("got %T, want *ecdsa.PublicKey", got)
			}
			if pub.X.Cmp(key.X) != 0 || pub.Y.Cmp(key.Y) != 0 {
				t.Fatal("reconstructed EC key does not match")
			}
		})
	}

	// A point off the curve must be rejected, not used.
	if _, err := publicKeyFromJWK(map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}),
		"y": base64.RawURLEncoding.EncodeToString([]byte{4, 5, 6}),
	}); err == nil {
		t.Fatal("expected an error for a point not on the curve")
	}
	if _, err := publicKeyFromJWK(map[string]interface{}{"kty": "OKP"}); err == nil {
		t.Fatal("expected an error for an unsupported key type")
	}
}
