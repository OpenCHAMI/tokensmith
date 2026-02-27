// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
//
// SPDX-License-Identifier: MIT

package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authz"
)

func TestAuthN_DefaultsRejectWrongIssuer(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := jwt.MapClaims{
		"sub": "u1",
		"iss": "wrong",
		"aud": []string{"svc"},
		"iat": time.Unix(100, 0).Unix(),
		"nbf": time.Unix(100, 0).Unix(),
		"exp": time.Unix(200, 0).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := tok.SignedString(priv)

	mw, err := Middleware(Options{
		Issuers:    []string{"iss"},
		Audiences:  []string{"svc"},
		StaticKeys: []crypto.PublicKey{&priv.PublicKey},
		now:        func() time.Time { return time.Unix(150, 0) },
	})
	if err != nil {
		t.Fatalf("middleware init: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("Authorization", "Bearer "+s)
	rr := httptest.NewRecorder()

	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if called {
		t.Fatalf("next should not be called")
	}
	if strings.Contains(rr.Body.String(), s) {
		t.Fatalf("response must not include token string")
	}
}

func TestAuthN_DefaultsRejectWrongAudience(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := jwt.MapClaims{
		"sub": "u1",
		"iss": "iss",
		"aud": []string{"other"},
		"iat": time.Unix(100, 0).Unix(),
		"nbf": time.Unix(100, 0).Unix(),
		"exp": time.Unix(200, 0).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := tok.SignedString(priv)

	mw, err := Middleware(Options{
		Issuers:    []string{"iss"},
		Audiences:  []string{"svc"},
		StaticKeys: []crypto.PublicKey{&priv.PublicKey},
		now:        func() time.Time { return time.Unix(150, 0) },
	})
	if err != nil {
		t.Fatalf("middleware init: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("Authorization", "Bearer "+s)
	rr := httptest.NewRecorder()

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthN_ValidTokenPassesAndSetsPrincipal(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := jwt.MapClaims{
		"sub": "u1",
		"iss": "iss",
		"aud": []string{"svc"},
		"iat": time.Unix(100, 0).Unix(),
		"nbf": time.Unix(100, 0).Unix(),
		"exp": time.Unix(100, 0).Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, _ := tok.SignedString(priv)

	mw, err := Middleware(Options{
		Issuers:    []string{"iss"},
		Audiences:  []string{"svc"},
		ClockSkew:  2 * time.Minute,
		StaticKeys: []crypto.PublicKey{&priv.PublicKey},
		now:        func() time.Time { return time.Unix(100, 0).Add(10 * time.Second) },
		Mapper: func(ctx context.Context, token *jwt.Token, claims jwt.MapClaims) (authz.Principal, error) {
			return authz.Principal{ID: "u1", Roles: []string{"r1"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("middleware init: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("Authorization", "Bearer "+s)
	rr := httptest.NewRecorder()

	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.ID != "u1" {
			t.Fatalf("expected principal in context")
		}
	}))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !called {
		t.Fatalf("expected next called")
	}
}

func TestAuthN_JWKSFetchFailureFailsClosedWithoutCache(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := jwt.MapClaims{
		"sub": "u1",
		"iss": "iss",
		"aud": []string{"svc"},
		"iat": time.Unix(100, 0).Unix(),
		"nbf": time.Unix(100, 0).Unix(),
		"exp": time.Unix(200, 0).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k1"
	s, _ := tok.SignedString(priv)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mw, err := Middleware(Options{
		Issuers:    []string{"iss"},
		Audiences:  []string{"svc"},
		JWKSURLs:   []string{srv.URL},
		HTTPClient: srv.Client(),
		now:        func() time.Time { return time.Unix(150, 0) },
	})
	if err != nil {
		t.Fatalf("middleware init: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("Authorization", "Bearer "+s)
	rr := httptest.NewRecorder()

	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}
