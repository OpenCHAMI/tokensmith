// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	tstoken "github.com/openchami/tokensmith/pkg/token"
)

func TestLargeLegacyTokenRemainsRoutable(t *testing.T) {
	// Given an otherwise valid legacy JWT above the human-only size cap.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := validTokenSmithClaims("iss", []string{"svc"})
	claims["sub"] = strings.Repeat("a", 9000)
	j := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	setRFC7638KID(t, j, &key.PublicKey)
	raw, err := j.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 8192 {
		t.Fatal("fixture is not large")
	}
	// When selecting and authenticating, then preserve legacy acceptance.
	profile, err := tstoken.SelectProfile(raw)
	if err != nil || profile != tstoken.ProfileLegacyV1 {
		t.Fatalf("legacy routing: %q %v", profile, err)
	}
	mw, err := Middleware(Options{Issuers: []string{"iss"}, Audiences: []string{"svc"}, StaticKeys: []crypto.PublicKey{&key.PublicKey}, now: func() time.Time { return time.Unix(150, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("legacy authentication: %d", w.Code)
	}
}
