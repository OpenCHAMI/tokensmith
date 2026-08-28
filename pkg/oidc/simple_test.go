// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimpleProvider_IntrospectTokenRemotelyEncodesFormToken(t *testing.T) {
	const tokenValue = "opaque+token&with=reserved%chars and spaces"
	const clientID = "tokensmith-client"
	const clientSecret = "client-secret"

	var sawIntrospection bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeProviderMetadata(t, w, r, ProviderMetadata{
				Issuer:                "issuer",
				IntrospectionEndpoint: "http://" + r.Host + "/introspect",
				JWKSURI:               "http://" + r.Host + "/jwks",
			})
		case "/introspect":
			sawIntrospection = true
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
			gotClientID, gotClientSecret, ok := r.BasicAuth()
			require.True(t, ok)
			require.Equal(t, clientID, gotClientID)
			require.Equal(t, clientSecret, gotClientSecret)
			require.NoError(t, r.ParseForm())
			require.Equal(t, tokenValue, r.FormValue("token"))

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":true,"username":"csm-admin","exp":4102444800,"iat":1700000000,"claims":{"sub":"csm-admin"},"token_type":"Bearer"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	provider := NewSimpleProvider(server.URL, clientID, clientSecret)
	introspection, err := provider.IntrospectToken(context.Background(), tokenValue)

	require.NoError(t, err)
	require.True(t, sawIntrospection)
	require.NotNil(t, introspection)
	assert.True(t, introspection.Active)
	assert.Equal(t, "csm-admin", introspection.Username)
}

func TestSimpleProvider_IntrospectTokenRemotelyClassifiesFailures(t *testing.T) {
	const secretToken = "secret-token-never-log"
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		wantKind error
	}{
		{
			name: "upstream rejected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "nope", http.StatusUnauthorized)
			},
			wantKind: ErrUpstreamRejected,
		},
		{
			name: "invalid json response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("not-json"))
			},
			wantKind: ErrInvalidResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					writeProviderMetadata(t, w, r, ProviderMetadata{
						Issuer:                "issuer",
						IntrospectionEndpoint: "http://" + r.Host + "/introspect",
						JWKSURI:               "http://" + r.Host + "/jwks",
					})
				case "/introspect":
					test.handler(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)

			provider := NewSimpleProvider(server.URL, "client", "secret")
			_, err := provider.IntrospectToken(context.Background(), secretToken)

			require.Error(t, err)
			assert.True(t, errors.Is(err, test.wantKind), "error %v should match %v", err, test.wantKind)
			assert.NotContains(t, err.Error(), secretToken)
		})
	}
}

func TestSimpleProvider_IntrospectTokenRemotelyClassifiesUnavailableProvider(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProviderMetadata(t, w, r, ProviderMetadata{
			Issuer:                "issuer",
			IntrospectionEndpoint: "http://127.0.0.1:1/introspect",
			JWKSURI:               "http://127.0.0.1:1/jwks",
		})
	}))
	t.Cleanup(server.Close)

	provider := NewSimpleProvider(server.URL, "tokensmith", "secret")
	_, err := provider.IntrospectToken(context.Background(), "secret-token-never-log")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUpstreamUnavailable), "error %v should match %v", err, ErrUpstreamUnavailable)
	assert.NotContains(t, err.Error(), "secret-token-never-log")
}

func writeProviderMetadata(t *testing.T, w http.ResponseWriter, r *http.Request, metadata ProviderMetadata) {
	t.Helper()
	require.Equal(t, http.MethodGet, r.Method)
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(metadata))
}

func TestProviderErrorUnwrapsKindAndCause(t *testing.T) {
	cause := errors.New("transport cause")
	err := providerError("introspect token", ErrUpstreamUnavailable, cause)

	assert.True(t, errors.Is(err, ErrUpstreamUnavailable))
	assert.True(t, errors.Is(err, cause))
	assert.False(t, strings.Contains(err.Error(), cause.Error()))
}

func TestSimpleProvider_IntrospectTokenValidatesJWKSOnFirstUse(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var introspectionCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeProviderMetadata(t, w, r, ProviderMetadata{
				Issuer:                "issuer",
				IntrospectionEndpoint: "http://" + r.Host + "/introspect",
				JWKSURI:               "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(rsaJWKS("key-1", &privateKey.PublicKey)))
		case "/introspect":
			introspectionCalls++
			http.Error(w, "local validation should handle this token", http.StatusTeapot)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	tokenValue := signedRS256Token(t, privateKey, "key-1", jwt.MapClaims{
		"iss":   server.URL,
		"sub":   "csm-admin",
		"aud":   "tokensmith",
		"scope": "openid profile",
		"iat":   float64(time.Now().Add(-time.Minute).Unix()),
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
	})

	provider := NewSimpleProvider(server.URL, "tokensmith", "secret")
	introspection, err := provider.IntrospectToken(context.Background(), tokenValue)

	require.NoError(t, err)
	require.NotNil(t, introspection)
	assert.True(t, introspection.Active)
	assert.Equal(t, "csm-admin", introspection.Username)
	assert.Equal(t, int64(introspection.Claims["exp"].(float64)), introspection.ExpiresAt)
	assert.Equal(t, 0, introspectionCalls)
}

func TestSimpleProvider_IntrospectTokenRejectsJWTWhenJWKSKeyIsUnknown(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var introspectionCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeProviderMetadata(t, w, r, ProviderMetadata{
				Issuer:                "issuer",
				IntrospectionEndpoint: "http://" + r.Host + "/introspect",
				JWKSURI:               "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}}))
		case "/introspect":
			introspectionCalls++
			http.Error(w, "should not introspect invalid JWT", http.StatusTeapot)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	tokenValue := signedRS256Token(t, privateKey, "missing-key", jwt.MapClaims{
		"iss": server.URL,
		"aud": "client",
		"sub": "remote-admin",
		"iat": float64(time.Now().Add(-time.Minute).Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	provider := NewSimpleProvider(server.URL, "client", "secret")
	introspection, err := provider.IntrospectToken(context.Background(), tokenValue)

	require.Error(t, err)
	assert.Nil(t, introspection)
	assert.True(t, errors.Is(err, ErrInvalidToken), "error %v should match %v", err, ErrInvalidToken)
	assert.Equal(t, 0, introspectionCalls)
}

func TestSimpleProvider_IntrospectTokenRejectsJWTWhenJWKSIsMalformed(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeProviderMetadata(t, w, r, ProviderMetadata{
				Issuer:                "issuer",
				IntrospectionEndpoint: "http://" + r.Host + "/introspect",
				JWKSURI:               "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			_, _ = w.Write([]byte(`{"keys":[{"kty":"RSA","kid":"key-1","n":"not-base64","e":"AQAB"}]}`))
		case "/introspect":
			http.Error(w, "should not introspect invalid JWT", http.StatusTeapot)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	tokenValue := signedRS256Token(t, privateKey, "key-1", jwt.MapClaims{
		"iss": server.URL,
		"aud": "client",
		"sub": "fallback-admin",
		"iat": float64(time.Now().Add(-time.Minute).Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	provider := NewSimpleProvider(server.URL, "client", "secret")
	introspection, err := provider.IntrospectToken(context.Background(), tokenValue)

	require.Error(t, err)
	assert.Nil(t, introspection)
	assert.True(t, errors.Is(err, ErrInvalidToken), "error %v should match %v", err, ErrInvalidToken)
}

func TestSimpleProvider_ValidateTokenLocallyRejectsWrongIssuerOrAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	provider := NewSimpleProvider("https://keycloak.example/realms/csm", "tokensmith", "secret")
	provider.jwks = rsaJWKS("key-1", &privateKey.PublicKey)

	tests := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name: "wrong issuer",
			claims: jwt.MapClaims{
				"iss": "https://evil.example/realms/csm",
				"aud": "tokensmith",
			},
		},
		{
			name: "wrong audience",
			claims: jwt.MapClaims{
				"iss": "https://keycloak.example/realms/csm",
				"aud": "other-client",
			},
		},
		{
			name: "missing audience",
			claims: jwt.MapClaims{
				"iss": "https://keycloak.example/realms/csm",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.claims["sub"] = "csm-admin"
			test.claims["iat"] = float64(time.Now().Add(-time.Minute).Unix())
			test.claims["exp"] = float64(time.Now().Add(time.Hour).Unix())
			tokenValue := signedRS256Token(t, privateKey, "key-1", test.claims)

			_, err := provider.validateTokenLocally(tokenValue)

			require.Error(t, err)
			assert.NotContains(t, err.Error(), tokenValue)
		})
	}
}

func TestSimpleProvider_IntrospectTokenDoesNotIntrospectWrongAudienceJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var introspectionCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeProviderMetadata(t, w, r, ProviderMetadata{
				Issuer:                "issuer",
				IntrospectionEndpoint: "http://" + r.Host + "/introspect",
				JWKSURI:               "http://" + r.Host + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(rsaJWKS("key-1", &privateKey.PublicKey))
		case "/introspect":
			introspectionCalls++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	tokenValue := signedRS256Token(t, privateKey, "key-1", jwt.MapClaims{
		"iss": server.URL,
		"aud": "other-client",
		"sub": "csm-admin",
		"iat": float64(time.Now().Add(-time.Minute).Unix()),
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	provider := NewSimpleProvider(server.URL, "tokensmith", "secret")
	_, err = provider.IntrospectToken(context.Background(), tokenValue)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidToken), "error %v should match %v", err, ErrInvalidToken)
	assert.Equal(t, 0, introspectionCalls)
}

func signedRS256Token(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signed
}

func rsaJWKS(kid string, publicKey *rsa.PublicKey) map[string]interface{} {
	return map[string]interface{}{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
			},
		},
	}
}
