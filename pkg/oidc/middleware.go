package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// TokenCtxKey is the context key for the OIDC token
type TokenCtxKey struct{}

// IntrospectionCtxKey is the context key for the OIDC introspection result
type IntrospectionCtxKey struct{}

// Helper to parse a JWKS map and return a map of kid to *rsa.PublicKey
func parseJWKS(jwks map[string]interface{}) (map[string]*rsa.PublicKey, error) {
	keys := make(map[string]*rsa.PublicKey)
	keyList, ok := jwks["keys"].([]interface{})
	if !ok {
		return nil, errors.New("invalid JWKS format: missing keys array")
	}
	for _, k := range keyList {
		keyMap, ok := k.(map[string]interface{})
		if !ok {
			continue
		}
		kid, _ := keyMap["kid"].(string)
		nStr, _ := keyMap["n"].(string)
		eVal, _ := keyMap["e"].(string)
		if kid == "" || nStr == "" || eVal == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eVal)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		keys[kid] = &rsa.PublicKey{N: n, E: e}
	}
	return keys, nil
}

// RequireToken is middleware that validates the presence and format of an OIDC token
func RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		// Add token to request context for downstream handlers
		ctx := context.WithValue(r.Context(), TokenCtxKey{}, parts[1])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireValidToken is middleware that validates the token with the OIDC provider
func RequireValidToken(provider Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from context (set by RequireToken middleware)
			token, ok := r.Context().Value(TokenCtxKey{}).(string)
			if !ok {
				http.Error(w, "Invalid token in context", http.StatusUnauthorized)
				return
			}

			var introspection *IntrospectionResponse
			var err error

			if provider.SupportsLocalIntrospection() {
				// Get JWKS for local validation
				jwksRaw, err := provider.GetJWKS(r.Context())
				if err != nil {
					http.Error(w, "Failed to get JWKS", http.StatusInternalServerError)
					return
				}
				jwks, ok := jwksRaw.(map[string]interface{})
				if !ok {
					http.Error(w, "Invalid JWKS format", http.StatusInternalServerError)
					return
				}
				keyMap, err := parseJWKS(jwks)
				if err != nil {
					http.Error(w, "Failed to parse JWKS", http.StatusInternalServerError)
					return
				}

				// Parse the JWT header to get the kid
				parsed, _ := gjwt.Parse(token, nil)
				kid, _ := parsed.Header["kid"].(string)
				pubKey, ok := keyMap[kid]
				if !ok {
					http.Error(w, "Key not found in JWKS", http.StatusUnauthorized)
					return
				}

				claims := gjwt.MapClaims{}
				parsedToken, err := gjwt.ParseWithClaims(token, claims, func(token *gjwt.Token) (interface{}, error) {
					return pubKey, nil
				})
				if err != nil || !parsedToken.Valid {
					http.Error(w, "Token validation failed", http.StatusUnauthorized)
					return
				}

				// Convert parsed token to introspection response
				introspection = &IntrospectionResponse{
					Active:    true,
					Username:  claims["sub"].(string),
					ExpiresAt: int64(claims["exp"].(float64)),
					IssuedAt:  int64(claims["iat"].(float64)),
					Claims:    claims,
					TokenType: "Bearer",
				}

				// Check if token is expired
				if time.Unix(introspection.ExpiresAt, 0).Before(time.Now()) {
					introspection.Active = false
				}
			} else {
				// Fall back to remote introspection
				introspection, err = provider.IntrospectToken(r.Context(), token)
				if err != nil {
					http.Error(w, "Token introspection failed", http.StatusUnauthorized)
					return
				}
			}

			if !introspection.Active {
				http.Error(w, "Token is not active", http.StatusUnauthorized)
				return
			}
			// Add introspection result to context for downstream handlers
			ctx := context.WithValue(r.Context(), IntrospectionCtxKey{}, introspection)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
