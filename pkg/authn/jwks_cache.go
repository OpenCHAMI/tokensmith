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

	"github.com/MicahParks/keyfunc/v3"
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
	defer resp.Body.Close() //nolint:errcheck
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
		keysForJWK, err := parseKeyfuncJWKSet(ctx, rk, opt.allowedAlgs)
		if err != nil {
			continue
		}
		for kid, key := range keysForJWK {
			switch key.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
				newKeys[kid] = key
			}
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

func parseKeyfuncJWKSet(ctx context.Context, rawJWK json.RawMessage, allowedAlgs map[string]struct{}) (map[string]crypto.PublicKey, error) {
	setJSON, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{rawJWK}})
	if err != nil {
		return nil, err
	}

	kf, err := keyfunc.NewJWKSetJSON(setJSON)
	if err != nil {
		return nil, err
	}

	jwksKeys, err := kf.Storage().KeyReadAll(ctx)
	if err != nil {
		return nil, err
	}

	keysByKID := make(map[string]crypto.PublicKey)
	for _, jwk := range jwksKeys {
		m := jwk.Marshal()
		if m.KID == "" {
			continue
		}
		if m.ALG != "" {
			if _, ok := allowedAlgs[string(m.ALG)]; !ok {
				continue
			}
		}

		pub, ok := jwk.Key().(crypto.PublicKey)
		if !ok {
			continue
		}
		keysByKID[m.KID] = pub
	}

	if len(keysByKID) == 0 {
		return nil, errors.New("no usable keys in jwk")
	}

	return keysByKID, nil
}
