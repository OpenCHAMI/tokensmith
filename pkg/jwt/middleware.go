package jwt

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	}
}

// keySetCache holds the JWKS cache and its metadata
type keySetCache struct {
	keySet jwk.Set
	mu     sync.RWMutex
}

// Middleware creates a new JWT middleware
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
				if err := keySet.refresh(opts.JWKSURL); err != nil {
					// Log error but don't panic
					// TODO: Add proper logging
				}
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

			// Parse and verify token
			var token jwt.Token
			var err error

			if keySet != nil {
				// Use JWKS
				token, err = jwt.ParseString(parts[1], jwt.WithKeySet(keySet.getKeySet()))
			} else {
				// Use provided key
				token, err = jwt.ParseString(parts[1], jwt.WithKey(jwa.RS256, key))
			}

			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Extract claims
			claims := &Claims{
				Issuer:         token.Issuer(),
				Subject:        token.Subject(),
				Audience:       token.Audience(),
				ExpirationTime: token.Expiration().Unix(),
				NotBefore:      token.NotBefore().Unix(),
				IssuedAt:       token.IssuedAt().Unix(),
			}

			// Extract custom claims
			if scope, ok := token.PrivateClaims()["scope"].([]interface{}); ok {
				claims.Scope = make([]string, len(scope))
				for i, v := range scope {
					if s, ok := v.(string); ok {
						claims.Scope[i] = s
					}
				}
			}
			if name, ok := token.PrivateClaims()["name"].(string); ok {
				claims.Name = name
			}
			if email, ok := token.PrivateClaims()["email"].(string); ok {
				claims.Email = email
			}
			if emailVerified, ok := token.PrivateClaims()["email_verified"].(bool); ok {
				claims.EmailVerified = emailVerified
			}

			// Validate claims based on options
			if opts.ValidateExpiration {
				if err := claims.Validate(); err != nil {
					http.Error(w, "token validation failed", http.StatusUnauthorized)
					return
				}
			}

			if opts.RequiredClaims != nil {
				rawClaims := token.PrivateClaims()
				for _, claim := range opts.RequiredClaims {
					if _, ok := rawClaims[claim]; !ok {
						http.Error(w, "missing required claim", http.StatusUnauthorized)
						return
					}
				}
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			// Add raw claims to context
			ctx = context.WithValue(ctx, RawClaimsContextKey, token.PrivateClaims())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// refresh fetches and updates the JWKS cache
func (c *keySetCache) refresh(url string) error {
	keySet, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.keySet = keySet
	return nil
}

// getKeySet returns the current JWKS
func (c *keySetCache) getKeySet() jwk.Set {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keySet
}

// GetClaimsFromContext retrieves the claims from the context
func GetClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	if !ok {
		return nil, ErrInvalidToken
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
				http.Error(w, "invalid token", http.StatusUnauthorized)
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
			// Get raw claims from token
			rawClaims, ok := r.Context().Value(RawClaimsContextKey).(map[string]interface{})
			if !ok || rawClaims == nil {
				http.Error(w, "invalid token type", http.StatusUnauthorized)
				return
			}

			// Check service-specific claims
			targetService, ok := rawClaims["target_service"].(string)
			if !ok || targetService != requiredService {
				http.Error(w, "invalid target service", http.StatusForbidden)
				return
			}

			// Verify service ID is present
			if _, ok := rawClaims["service_id"].(string); !ok {
				http.Error(w, "missing service ID", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
