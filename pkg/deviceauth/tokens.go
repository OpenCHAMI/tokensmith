package deviceauth

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims binds a user-session JWT to one provider, project, user and bounded session.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	ID        string   `json:"jti"`
	// Class "human" identifies the approving user, not the authentication method.
	Class               string `json:"token_class"`
	GitLabIssuer        string `json:"gitlab_issuer"`
	ProjectID           int64  `json:"gitlab_project_id"`
	UserID              int64  `json:"gitlab_user_id"`
	SessionID           string `json:"session_id"`
	ApprovedAt          int64  `json:"approved_at"`
	SessionExp          int64  `json:"session_exp"`
	MembershipCheckedAt int64  `json:"membership_checked_at"`
	Role                string `json:"role"`
}

// These accessors preserve the integer wire format while letting jwt validate
// registered claims directly, without a lossy MapClaims conversion.
func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}
func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}
func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}
func (c Claims) GetIssuer() (string, error)             { return c.Issuer, nil }
func (c Claims) GetSubject() (string, error)            { return c.Subject, nil }
func (c Claims) GetAudience() (jwt.ClaimStrings, error) { return c.Audience, nil }

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
	var claims Claims
	parsed, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" || t.Header["typ"] != "JWT" {
			return nil, ErrDenied
		}
		return lookup(kid)
	},
		jwt.WithValidMethods([]string{"PS256"}),
		jwt.WithIssuer(c.ClusterIssuer),
		jwt.WithAudience(c.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(time.Duration(c.SkewSeconds)*time.Second),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil || !parsed.Valid {
		return nil, ErrDenied
	}

	n := now.Unix()
	// Identity and token class cannot be borrowed from machine or CI tokens.
	if claims.Class != "human" || claims.GitLabIssuer != c.Issuer || claims.ProjectID != c.ProjectID ||
		claims.UserID <= 0 || claims.Subject != c.Issuer+"/user/"+decimal(claims.UserID) ||
		len(claims.Audience) != 1 || claims.Audience[0] != c.Audience ||
		(claims.Role != "admin" && claims.Role != "operator" && claims.Role != "viewer") ||
		claims.ID == "" || claims.SessionID == "" {
		return nil, ErrDenied
	}
	// Expiry has no extra leeway. Thirty seconds of clock offset is already
	// reserved by the issuance caps and the 300-second revocation budget.
	if claims.IssuedAt <= 0 || claims.NotBefore != claims.IssuedAt || claims.IssuedAt > n+c.SkewSeconds ||
		n >= claims.ExpiresAt || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > c.TokenSeconds {
		return nil, ErrDenied
	}
	if claims.ApprovedAt <= 0 || claims.ApprovedAt > claims.IssuedAt ||
		claims.SessionExp-claims.ApprovedAt != c.AbsoluteSeconds || n >= claims.SessionExp ||
		claims.ExpiresAt+c.SkewSeconds > claims.SessionExp {
		return nil, ErrDenied
	}
	if claims.MembershipCheckedAt < claims.ApprovedAt || claims.MembershipCheckedAt > claims.IssuedAt ||
		claims.IssuedAt-claims.MembershipCheckedAt > c.CacheSeconds ||
		claims.ExpiresAt > claims.MembershipCheckedAt+c.CacheSeconds+c.TokenSeconds {
		return nil, ErrDenied
	}

	return &claims, nil
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
