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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var errNoCachedKeys = errors.New("no cached JWKS keys")

type jwksCache struct {
	mu sync.RWMutex
	// keysByKID is the most recently fetched key set.
	keysByKID map[string]crypto.PublicKey
	// softExpiry is when we prefer to refresh but may continue using cached keys.
	softExpiry time.Time
	// hardExpiry is when cached keys are considered unusable.
	hardExpiry time.Time
}

type jwksCacheOptions struct {
	client       *http.Client
	softTTL      time.Duration
	hardTTL      time.Duration
	allowedAlgs  map[string]struct{}
	maxBodyBytes int64
}

func (o jwksCacheOptions) withDefaults() jwksCacheOptions {
	out := o
	if out.client == nil {
		out.client = http.DefaultClient
	}
	if out.softTTL == 0 {
		out.softTTL = 10 * time.Minute
	}
	if out.hardTTL == 0 {
		out.hardTTL = 1 * time.Hour
	}
	if out.maxBodyBytes == 0 {
		out.maxBodyBytes = 1 << 20 // 1MiB
	}
	if out.allowedAlgs == nil {
		out.allowedAlgs = map[string]struct{}{
			"RS256": {}, "RS384": {}, "RS512": {},
			"PS256": {}, "PS384": {}, "PS512": {},
			"ES256": {}, "ES384": {}, "ES512": {},
		}
	}
	return out
}

func newJWKSCache() *jwksCache { return &jwksCache{} }

func (c *jwksCache) shouldRefresh(now time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keysByKID == nil || now.After(c.softExpiry)
}

func (c *jwksCache) getKey(now time.Time, kid string) (crypto.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.keysByKID == nil || now.After(c.hardExpiry) {
		return nil, false
	}
	k, ok := c.keysByKID[kid]
	return k, ok
}

func (c *jwksCache) hasUsableKeys(now time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keysByKID != nil && !now.After(c.hardExpiry) && len(c.keysByKID) > 0
}

func (c *jwksCache) refresh(ctx context.Context, now time.Time, jwksURL string, opt jwksCacheOptions) error {
	opt = opt.withDefaults()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := opt.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("jwks fetch failed: status=%d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, opt.maxBodyBytes))
	if err != nil {
		return err
	}

	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}

	newKeys := make(map[string]crypto.PublicKey)
	for _, rk := range raw.Keys {
		var hdr struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			ALG string `json:"alg"`
		}
		_ = json.Unmarshal(rk, &hdr)
		if hdr.KID == "" {
			continue
		}
		if hdr.ALG != "" {
			if _, ok := opt.allowedAlgs[hdr.ALG]; !ok {
				continue
			}
		}

		pub, err := parseJWKSKey(rk)
		if err != nil {
			continue
		}
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			newKeys[hdr.KID] = pub
		}
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("jwks fetch succeeded but no usable keys")
	}

	c.mu.Lock()
	c.keysByKID = newKeys
	c.softExpiry = now.Add(opt.softTTL)
	c.hardExpiry = now.Add(opt.hardTTL)
	c.mu.Unlock()
	return nil
}

func parseJWKSKey(raw json.RawMessage) (crypto.PublicKey, error) {
	var base struct {
		KTY string `json:"kty"`
	}
	if err := json.Unmarshal(raw, &base); err != nil {
		return nil, err
	}

	switch base.KTY {
	case "RSA":
		var jwk struct {
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(raw, &jwk); err != nil {
			return nil, err
		}
		return rsaPublicKeyFromJWK(jwk.N, jwk.E)
	case "EC":
		var jwk struct {
			KTY string `json:"kty"`
			CRV string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		if err := json.Unmarshal(raw, &jwk); err != nil {
			return nil, err
		}
		return ecdsaPublicKeyFromJWK(jwk.CRV, jwk.X, jwk.Y)
	default:
		return nil, fmt.Errorf("unsupported kty %q", base.KTY)
	}
}
