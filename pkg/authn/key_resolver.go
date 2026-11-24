// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
// SPDX-License-Identifier: MIT

package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
)

type keyResolver struct {
	opt   Options
	cache *jwksCache
}

func (k keyResolver) resolve(ctx context.Context, t *jwt.Token, now time.Time) (crypto.PublicKey, error) {
	kid, ok := t.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, errors.New("missing kid header")
	}
	alg := t.Method.Alg()
	if err := keys.ValidateAlgorithm(alg); err != nil {
		return nil, err
	}
	if key, ok := k.cache.getKey(now, kid, alg); ok {
		return ensureAlgCompatibleKey(alg, key)
	}
	jwksOpt := jwksCacheOptions{client: k.opt.HTTPClient, softTTL: k.opt.JWKSCacheSoftTTL, hardTTL: k.opt.JWKSCacheHardTTL}
	if len(k.opt.JWKSURLs) > 0 && k.cache.shouldRefresh(now) {
		// Existing cache refresh semantics: retain usable keys on soft refresh failure.
		if err := refreshAllJWKS(ctx, k.cache, now, k.opt.JWKSURLs, jwksOpt); err == nil {
			if key, ok := k.cache.getKey(now, kid, alg); ok {
				return ensureAlgCompatibleKey(alg, key)
			}
		}
	}
	if key, ok := k.opt.staticKeysByKID[kid]; ok {
		return ensureAlgCompatibleKey(alg, key)
	}
	if len(k.opt.JWKSURLs) > 0 && !k.cache.hasUsableKeys(now) {
		if err := refreshAllJWKS(ctx, k.cache, now, k.opt.JWKSURLs, jwksOpt); err != nil {
			return nil, err
		}
		if key, ok := k.cache.getKey(now, kid, alg); ok {
			return ensureAlgCompatibleKey(alg, key)
		}
	}
	return nil, errors.New("no matching verification key")
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
