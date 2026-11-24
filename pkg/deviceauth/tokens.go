package deviceauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/token"
)

// Claims is the shared, integer-preserving human-session contract.
// Deprecated: use token.HumanSessionClaims for consumer code.
type Claims = token.HumanSessionClaims

type publicKey struct {
	key   *rsa.PublicKey
	until time.Time
}

// KeyRing rotation retains only public verification keys for the maximum token
// lifetime plus skew. No old private key is retained. Persist the active private
// key through the existing TokenSmith key mechanism; restart expires sessions.
type KeyRing struct {
	mu      sync.RWMutex
	active  string
	private *rsa.PrivateKey
	public  map[string]publicKey
}

// NewKeyRing requires a named RSA signing key of at least 2048 bits.
func NewKeyRing(kid string, key *rsa.PrivateKey) (*KeyRing, error) {
	if kid == "" || key == nil || key.N == nil || key.N.BitLen() < 2048 {
		return nil, ErrDenied
	}
	return &KeyRing{
		active:  kid,
		private: key,
		public: map[string]publicKey{
			kid: {key: &key.PublicKey},
		},
	}, nil
}

// Rotate signs with the new key and retains old public keys for 210 seconds.
func (k *KeyRing) Rotate(kid string, key *rsa.PrivateKey, now time.Time) error {
	if kid == "" || key == nil || key.N == nil || key.N.BitLen() < 2048 {
		return ErrDenied
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.public[kid]; exists {
		return ErrDenied
	}
	previous := k.public[k.active]
	previous.until = now.Add(210 * time.Second)
	k.public[k.active] = previous
	for id, p := range k.public {
		if !p.until.IsZero() && !now.Before(p.until) {
			delete(k.public, id)
		}
	}
	k.active = kid
	k.private = key
	k.public[kid] = publicKey{key: &key.PublicKey}
	return nil
}

// Sign issues a PS256 JWT; the authority supplies the verified claim values.
func (k *KeyRing) Sign(c Claims) (string, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	t := jwt.NewWithClaims(jwt.SigningMethodPS256, c)
	t.Header["kid"] = k.active
	t.Header["typ"] = "JWT"
	return t.SignedString(k.private)
}

// JWKS publishes active and still-valid retired public keys, never private keys.
func (k *KeyRing) JWKS(now time.Time) any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	list := []map[string]string{}
	for kid, p := range k.public {
		if !p.until.IsZero() && !now.Before(p.until) {
			continue
		}
		list = append(list, map[string]string{
			"kty": "RSA",
			"use": "sig",
			"alg": "PS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
		})
	}
	return map[string]any{"keys": list}
}

// Verify is the required user-session token contract for downstream route authorization.
// Callers must select keys only from the fixed cluster issuer's JWKS, bound the
// JWKS cache through rotation, and authorize actual routes against Role. A valid
// signature alone is insufficient. The skew budget covers the total issuer to
// verifier clock offset. Expiry is strict: parser leeway is only useful for
// iat/nbf; adding expiry leeway would spend the clock budget twice. The caller
// must fail closed if trusted clock error cannot be bounded by SkewSeconds.
func Verify(raw string, c Config, now time.Time, lookup func(string) (*rsa.PublicKey, error)) (*Claims, error) {
	if c.Validate() != nil || len(raw) > 8192 {
		return nil, ErrDenied
	}
	if lookup == nil {
		return nil, ErrDenied
	}
	claims, err := token.VerifyHumanSession(context.Background(), raw, token.HumanSessionVerification{
		Policy: c.ConsumerPolicy(),
		Now:    now,
		Lookup: func(_ context.Context, kid string) (*rsa.PublicKey, error) { return lookup(kid) },
	})
	if err != nil {
		return nil, ErrDenied
	}
	return claims, nil
}

// Verify applies the user-session token contract using this ring's public keys.
func (k *KeyRing) Verify(raw string, c Config, now time.Time) (*Claims, error) {
	return Verify(raw, c, now, func(id string) (*rsa.PublicKey, error) {
		k.mu.RLock()
		defer k.mu.RUnlock()
		p, ok := k.public[id]
		if !ok || !p.until.IsZero() && !now.Before(p.until) {
			return nil, ErrDenied
		}
		return p.key, nil
	})
}

func decimal(n int64) string { return strconv.FormatInt(n, 10) }
