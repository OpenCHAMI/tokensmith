package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWKSCache_RefreshAndUseCachedOnSoftExpiry(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid1 := "k1"

	jwks1 := jwksJSON(t, kid1, &key1.PublicKey)

	stage := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stage == 1 {
			_, _ = w.Write(jwks1)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := newJWKSCache()
	now := time.Unix(100, 0)
	opt := jwksCacheOptions{softTTL: 1 * time.Second, hardTTL: 10 * time.Second, client: srv.Client()}

	if err := cache.refresh(context.Background(), now, srv.URL, opt); err != nil {
		t.Fatalf("refresh err: %v", err)
	}
	if _, ok := cache.getKey(now, kid1); !ok {
		t.Fatalf("expected kid1 cached")
	}

	// After soft-expiry, refresh fails but cached key should still be usable.
	stage = 2
	now2 := now.Add(2 * time.Second)
	if cache.shouldRefresh(now2) {
		_ = cache.refresh(context.Background(), now2, srv.URL, opt)
	}
	if _, ok := cache.getKey(now2, kid1); !ok {
		t.Fatalf("expected cached key still usable before hard-expiry")
	}
}

func TestJWKSCache_HardExpiryInvalidatesKeys(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid1 := "k1"
	jwks1 := jwksJSON(t, kid1, &key1.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks1)
	}))
	defer srv.Close()

	cache := newJWKSCache()
	now := time.Unix(100, 0)
	opt := jwksCacheOptions{softTTL: 1 * time.Second, hardTTL: 2 * time.Second, client: srv.Client()}

	if err := cache.refresh(context.Background(), now, srv.URL, opt); err != nil {
		t.Fatalf("refresh err: %v", err)
	}
	if _, ok := cache.getKey(now, kid1); !ok {
		t.Fatalf("expected kid1 cached")
	}

	nowExpired := now.Add(3 * time.Second)
	if _, ok := cache.getKey(nowExpired, kid1); ok {
		t.Fatalf("expected key unusable after hard-expiry")
	}
}

func jwksJSON(t *testing.T, kid string, pub *rsa.PublicKey) []byte {
	t.Helper()

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	obj := map[string]any{
		"keys": []any{
			map[string]any{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"use": "sig",
				"n":   n,
				"e":   e,
			},
		},
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}
