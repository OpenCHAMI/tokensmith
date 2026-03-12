// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/keys"
)

// Mode controls behavior when authentication fails.
//
// AuthN is expected to be fail-closed by default.
// AuthNOff exists only for explicit opt-out.
type Mode int

const (
	AuthNEnforce Mode = iota
	AuthNOff
)

type nowFunc func() time.Time

// PrincipalMapper maps verified JWT claims into an authz.Principal.
//
// Services should avoid placing sensitive data in the principal.
// Returning an error fails the request.
//
// Implementations MUST NOT log the raw token.
type PrincipalMapper func(ctx context.Context, token *jwt.Token, claims jwt.MapClaims) (authz.Principal, error)

type Options struct {
	Mode Mode

	// ValidateIssuer enables issuer validation (default true).
	// Disable explicitly by setting this field to false.
	ValidateIssuer          bool
	DisableIssuerValidation bool
	Issuers                 []string

	// ValidateAudience enables audience validation (default true).
	// Disable explicitly by setting this field to false.
	ValidateAudience          bool
	DisableAudienceValidation bool
	Audiences                 []string

	// ClockSkew is the allowed clock skew for exp/nbf checks.
	// Default 2m. Maximum 10m.
	ClockSkew time.Duration

	StaticKeys []crypto.PublicKey
	JWKSURLs   []string

	// Deterministic JWKS caching.
	JWKSCacheSoftTTL time.Duration
	JWKSCacheHardTTL time.Duration

	HTTPClient *http.Client

	Mapper PrincipalMapper

	now nowFunc
}

func (o Options) withDefaults() (Options, error) {
	out := o
	if out.Mode == 0 {
		out.Mode = AuthNEnforce
	}

	// Defaults: issuer/audience validation ON. Disabling requires an explicit option.
	out.ValidateIssuer = !out.DisableIssuerValidation
	out.ValidateAudience = !out.DisableAudienceValidation

	if out.ClockSkew == 0 {
		out.ClockSkew = 2 * time.Minute
	}
	if out.ClockSkew > 10*time.Minute {
		return Options{}, errors.New("clock skew too large (max 10m)")
	}
	if out.HTTPClient == nil {
		out.HTTPClient = http.DefaultClient
	}
	if out.JWKSCacheSoftTTL == 0 {
		out.JWKSCacheSoftTTL = 10 * time.Minute
	}
	if out.JWKSCacheHardTTL == 0 {
		out.JWKSCacheHardTTL = 1 * time.Hour
	}
	if out.now == nil {
		out.now = time.Now
	}
	if out.Mapper == nil {
		out.Mapper = func(ctx context.Context, token *jwt.Token, claims jwt.MapClaims) (authz.Principal, error) {
			sub, _ := claims["sub"].(string)
			return authz.Principal{ID: sub}, nil
		}
	}

	if out.ValidateIssuer && len(out.Issuers) == 0 {
		return Options{}, errors.New("issuer validation enabled but no issuers configured")
	}
	if out.ValidateAudience && len(out.Audiences) == 0 {
		return Options{}, errors.New("audience validation enabled but no audiences configured")
	}
	if len(out.StaticKeys) == 0 && len(out.JWKSURLs) == 0 {
		return Options{}, errors.New("no JWT verification keys configured (StaticKeys or JWKSURLs required)")
	}
	return out, nil
}

func Middleware(opt Options) (func(http.Handler) http.Handler, error) {
	opt, err := opt.withDefaults()
	if err != nil {
		return nil, err
	}

	cache := newJWKSCache()
	jwksOpt := jwksCacheOptions{
		client:  opt.HTTPClient,
		softTTL: opt.JWKSCacheSoftTTL,
		hardTTL: opt.JWKSCacheHardTTL,
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opt.Mode == AuthNOff {
				next.ServeHTTP(w, r)
				return
			}

			tokStr, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}

			now := opt.now()

			parserOpts := []jwt.ParserOption{
				jwt.WithValidMethods(keys.GetFIPSApprovedAlgorithms()),
				jwt.WithLeeway(opt.ClockSkew),
				jwt.WithExpirationRequired(),
				jwt.WithIssuedAt(),
				jwt.WithTimeFunc(func() time.Time { return now }),
			}
			parser := jwt.NewParser(parserOpts...)

			token, err := parser.Parse(tokStr, func(t *jwt.Token) (any, error) {
				kid, _ := t.Header["kid"].(string)
				alg := t.Method.Alg()

				if err := keys.ValidateAlgorithm(alg); err != nil {
					return nil, err
				}

				if kid != "" {
					if k, ok := cache.getKey(now, kid); ok {
						return ensureAlgCompatibleKey(alg, k)
					}

					// Prefer cached keys; refresh opportunistically.
					if len(opt.JWKSURLs) > 0 && cache.shouldRefresh(now) {
						_ = refreshAllJWKS(r.Context(), cache, now, opt.JWKSURLs, jwksOpt)
						if k, ok := cache.getKey(now, kid); ok {
							return ensureAlgCompatibleKey(alg, k)
						}
					}
				}

				// Try static keys.
				for _, k := range opt.StaticKeys {
					if _, err := ensureAlgCompatibleKey(alg, k); err != nil {
						continue
					}
					return k, nil
				}

				// If we have no usable cached keys, refresh once (fail closed if fetch fails).
				if len(opt.JWKSURLs) > 0 && !cache.hasUsableKeys(now) {
					if err := refreshAllJWKS(r.Context(), cache, now, opt.JWKSURLs, jwksOpt); err != nil {
						return nil, err
					}
					if kid != "" {
						if k, ok := cache.getKey(now, kid); ok {
							return ensureAlgCompatibleKey(alg, k)
						}
					}
				}

				return nil, errors.New("no matching verification key")
			})
			if err != nil || token == nil || !token.Valid {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			mapClaims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "invalid token claims", http.StatusUnauthorized)
				return
			}

			// Additional issuer/audience checks. jwt/v5 helpers are not variadic.
			if opt.ValidateIssuer {
				iss, _ := mapClaims["iss"].(string)
				if !stringInSlice(iss, opt.Issuers) {
					http.Error(w, "invalid token", http.StatusUnauthorized)
					return
				}
			}
			if opt.ValidateAudience {
				audOK := false
				if audRaw, ok := mapClaims["aud"]; ok {
					switch v := audRaw.(type) {
					case string:
						audOK = stringInSlice(v, opt.Audiences)
					case []any:
						for _, it := range v {
							if s, ok := it.(string); ok && stringInSlice(s, opt.Audiences) {
								audOK = true
								break
							}
						}
					case []string:
						for _, s := range v {
							if stringInSlice(s, opt.Audiences) {
								audOK = true
								break
							}
						}
					}
				}
				if !audOK {
					http.Error(w, "invalid token", http.StatusUnauthorized)
					return
				}
			}

			p, err := opt.Mapper(r.Context(), token, mapClaims)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := ContextWithPrincipal(r.Context(), p)
			ctx = ContextWithVerifiedClaims(ctx, mapClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}, nil
}

func refreshAllJWKS(ctx context.Context, cache *jwksCache, now time.Time, urls []string, opt jwksCacheOptions) error {
	var lastErr error
	for _, u := range urls {
		if err := cache.refresh(ctx, now, u, opt); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		return errNoCachedKeys
	}
	return lastErr
}

func bearerToken(authzHeader string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(authzHeader), " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	if parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func stringInSlice(s string, list []string) bool {
	for _, it := range list {
		if it == s {
			return true
		}
	}
	return false
}

func ensureAlgCompatibleKey(alg string, k crypto.PublicKey) (crypto.PublicKey, error) {
	switch {
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		if _, ok := k.(*rsa.PublicKey); !ok {
			return nil, errors.New("alg requires RSA key")
		}
	case strings.HasPrefix(alg, "ES"):
		if _, ok := k.(*ecdsa.PublicKey); !ok {
			return nil, errors.New("alg requires ECDSA key")
		}
	case strings.HasPrefix(alg, "Ed"):
		if _, ok := k.(ed25519.PublicKey); !ok {
			return nil, errors.New("alg requires Ed25519 key")
		}
	default:
		return nil, errors.New("unsupported alg")
	}
	return k, nil
}
