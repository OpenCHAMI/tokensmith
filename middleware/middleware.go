package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
)

// ContextKey is the key used to store the claims in the context
type ContextKey string

const (
	// ClaimsContextKey is the key used to store the claims in the context
	ClaimsContextKey ContextKey = "jwt_claims"
	// RawClaimsContextKey is the key used to store raw claims in the context
	RawClaimsContextKey ContextKey = "jwt_raw_claims"
)

// MiddlewareOptions contains options for the JWT middleware
type MiddlewareOptions struct {
	// AllowEmptyToken allows requests without a token
	AllowEmptyToken bool
	// ValidateExpiration enables expiration validation
	ValidateExpiration bool
	// ValidateIssuer enables issuer validation
	ValidateIssuer bool
	// ValidateAudience enables audience validation
	ValidateAudience bool
	// RequiredClaims is a list of claims that are required to be present in the token
	RequiredClaims []string
	// JWKSURL is the URL to fetch the JSON Web Key Set from
	JWKSURL string
	// JWKSRefreshInterval is how often to refresh the JWKS cache
	JWKSRefreshInterval time.Duration
	// NonEnforcing allows the middleware to skip validation checks.  It still logs errors.
	NonEnforcing bool
}

// DefaultMiddlewareOptions returns the default middleware options
func DefaultMiddlewareOptions() *MiddlewareOptions {
	return &MiddlewareOptions{
		AllowEmptyToken:     false,
		ValidateExpiration:  true,
		ValidateIssuer:      true,
		ValidateAudience:    true,
		RequiredClaims:      []string{"sub", "iss", "aud"},
		JWKSRefreshInterval: 1 * time.Hour,
		NonEnforcing:        false,
	}
}

// keySetCache holds the JWKS cache and its metadata
type keySetCache struct {
	keySet map[string]interface{}
	mu     sync.RWMutex
}

// JWTMiddleware creates a new JWT middleware using golang-jwt/jwt/v5
func JWTMiddleware(key interface{}, opts *MiddlewareOptions) func(http.Handler) http.Handler {
	if opts == nil {
		opts = DefaultMiddlewareOptions()
	}

	var keySet *keySetCache
	if opts.JWKSURL != "" {
		keySet = &keySetCache{}
		// Initial fetch of JWKS
		if err := keySet.refresh(opts.JWKSURL); err != nil {
			panic(err)
		}
		// Start background refresh
		go func() {
			ticker := time.NewTicker(opts.JWKSRefreshInterval)
			defer ticker.Stop()
			for range ticker.C {
				_ = keySet.refresh(opts.JWKSURL)
			}
		}()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				if opts.AllowEmptyToken {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			// Check if it's a Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			claims := &token.TSClaims{}
			var idtoken *jwt.Token
			var err error

			keyFunc := func(idtoken *jwt.Token) (interface{}, error) {
				// Validate the algorithm is FIPS-approved
				if err := keys.ValidateAlgorithm(idtoken.Method.Alg()); err != nil {
					return nil, fmt.Errorf("invalid algorithm: %w", err)
				}

				// If JWKS is used, select key by kid
				if keySet != nil {
					if kid, ok := idtoken.Header["kid"].(string); ok {
						keySet.mu.RLock()
						defer keySet.mu.RUnlock()
						if k, found := keySet.keySet[kid]; found {
							return k, nil
						}
						return nil, errors.New("key not found in JWKS")
					}
					return nil, errors.New("no kid in token header")
				}
				return key, nil
			}

			idtoken, err = jwt.ParseWithClaims(tokenString, claims, keyFunc)
			if err != nil || !idtoken.Valid {
				http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Validate claims using TSClaims.Validate
			if opts.ValidateExpiration {
				if err := claims.Validate(!opts.NonEnforcing); err != nil {
					http.Error(w, "token validation failed: "+err.Error(), http.StatusUnauthorized)
					return
				}
			}

			// Required claims check
			if opts.RequiredClaims != nil {
				for _, claim := range opts.RequiredClaims {
					switch claim {
					case "sub":
						if claims.Subject == "" {
							http.Error(w, "missing required claim: sub", http.StatusUnauthorized)
							return
						}
					case "iss":
						if claims.Issuer == "" {
							http.Error(w, "missing required claim: iss", http.StatusUnauthorized)
							return
						}
					case "aud":
						if len(claims.Audience) == 0 {
							http.Error(w, "missing required claim: aud", http.StatusUnauthorized)
							return
						}
					default:
						// For custom claims, use reflection or mapstructure if needed
					}
				}
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			// Add raw claims to context (as map[string]interface{})
			if mapClaims, ok := idtoken.Claims.(*token.TSClaims); ok {
				ctx = context.WithValue(ctx, RawClaimsContextKey, mapClaims)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// refresh fetches and updates the JWKS cache (expects JWKS as a map of kid to key)
func (c *keySetCache) refresh(url string) error {
	jwks, err := keyfunc.Get(url, keyfunc.Options{})
	if err != nil {
		return err
	}

	newKeySet := make(map[string]interface{})
	for kid, key := range jwks.ReadOnlyKeys() {
		if key == nil {
			continue
		}
		newKeySet[kid] = key
	}

	c.mu.Lock()
	c.keySet = newKeySet
	c.mu.Unlock()
	return nil
}

// GetClaimsFromContext retrieves the JWT claims from the request context
func GetClaimsFromContext(ctx context.Context) (*token.TSClaims, error) {
	claims, ok := ctx.Value(ClaimsContextKey).(*token.TSClaims)
	if !ok {
		return nil, errors.New("claims not found in context")
	}
	return claims, nil
}

// GetRawClaimsFromContext retrieves the raw JWT claims from the request context
func GetRawClaimsFromContext(ctx context.Context) (*token.TSClaims, error) {
	claims, ok := ctx.Value(RawClaimsContextKey).(*token.TSClaims)
	if !ok {
		return nil, errors.New("raw claims not found in context")
	}
	return claims, nil
}

// RequireScope creates a middleware that checks if the token has the required scope
func RequireScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Check if the required scope is present
			hasScope := false
			for _, scope := range claims.Scope {
				if scope == requiredScope {
					hasScope = true
					break
				}
			}

			if !hasScope {
				http.Error(w, "insufficient scope", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireScopes creates a middleware that checks if the token has all the required scopes
func RequireScopes(requiredScopes []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			// Check if all required scopes are present
			for _, requiredScope := range requiredScopes {
				hasScope := false
				for _, scope := range claims.Scope {
					if scope == requiredScope {
						hasScope = true
						break
					}
				}
				if !hasScope {
					http.Error(w, "insufficient scope", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireServiceToken creates middleware that validates service-to-service tokens
func RequireServiceToken(requiredService string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawClaims, err := GetRawClaimsFromContext(r.Context())
			if err != nil || rawClaims == nil {
				http.Error(w, "invalid token type", http.StatusUnauthorized)
				return
			}
			// Check service-specific claims
			if rawClaims.ClusterID != requiredService {
				http.Error(w, "invalid target service", http.StatusForbidden)
				return
			}
			if rawClaims.OpenCHAMIID == "" {
				http.Error(w, "missing service ID", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
