// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestHumanTrustedKeysAndLookupRedaction(t *testing.T) {
	x := newProfileFixture(t)
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"static", "https jwks", "named lookup"} {
		t.Run(source, func(t *testing.T) {
			// Given a fixed trusted key source, when verified, then only its key works.
			o := x.opt
			kidToken := jwt.NewWithClaims(jwt.SigningMethodPS256, x.claims)
			setRFC7638KID(t, kidToken, &x.key.PublicKey)
			if source == "https jwks" {
				doc := bytes.ReplaceAll(jwksJSON(t, "named-ring-key", &x.key.PublicKey), []byte(`"RS256"`), []byte(`"PS256"`))
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := w.Write(doc); err != nil {
						t.Error(err)
					}
				}))
				defer srv.Close()
				o.StaticKeys = nil
				o.JWKSURLs = []string{srv.URL}
				o.HTTPClient = srv.Client()
				kidToken.Header["kid"] = "named-ring-key"
			}
			if source == "named lookup" {
				o.StaticKeys = nil
				o.HumanSessionKeyLookup = func(_ context.Context, kid string) (*rsa.PublicKey, error) {
					if kid != "named-ring-key" {
						return nil, errors.New("unknown key")
					}
					return &x.key.PublicKey, nil
				}
				kidToken.Header["kid"] = "named-ring-key"
			}
			for _, mode := range []string{"valid", "unknown kid", "wrong signature"} {
				t.Run(mode, func(t *testing.T) {
					j := *kidToken
					j.Header = map[string]any{"alg": "PS256", "typ": "JWT", "kid": kidToken.Header["kid"]}
					key := x.key
					if mode == "unknown kid" {
						j.Header["kid"] = "unknown"
					}
					if mode == "wrong signature" {
						key = wrong
					}
					raw, err := j.SignedString(key)
					if err != nil {
						t.Fatal(err)
					}
					w, ctx := serveProfile(t, o, raw)
					if mode == "valid" {
						if w.Code != 204 || ctx == nil {
							t.Fatalf("trusted key rejected: %d", w.Code)
						}
					} else if w.Code != 401 || ctx != nil {
						t.Fatal("untrusted key reached handler")
					}
				})
			}
		})
	}
	// Given a failing explicit lookup and a valid static fallback, when verified,
	// then deny once and redact private error text from both logs and response.
	var logs bytes.Buffer
	oldLog := log.Logger
	log.Logger = zerolog.New(&logs)
	defer func() { log.Logger = oldLog }()
	calls := 0
	o := x.opt
	o.HumanSessionKeyLookup = func(context.Context, string) (*rsa.PublicKey, error) {
		calls++
		return nil, errors.New("private-lookup-credential")
	}
	w, ctx := serveProfile(t, o, x.sign(t, x.claims))
	if w.Code != 401 || ctx != nil || calls != 1 {
		t.Fatal("lookup failure fell back")
	}
	if strings.Contains(logs.String()+w.Body.String(), "private-lookup-credential") {
		t.Fatal("private lookup error leaked")
	}
	// Given a nil or wrong explicit key, when verified, then do not fall back.
	for _, key := range []*rsa.PublicKey{nil, &wrong.PublicKey, {}} {
		o.HumanSessionKeyLookup = func(context.Context, string) (*rsa.PublicKey, error) { return key, nil }
		w, ctx := serveProfile(t, o, x.sign(t, x.claims))
		if w.Code != 401 || ctx != nil {
			t.Fatal("invalid explicit key accepted")
		}
	}
}
