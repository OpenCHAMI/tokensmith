package deviceauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/token"
)

// tokenFixture supplies explicit valid claims without a session authority or
// network calls, so consumers can test the JWT contract independently.
type tokenFixture struct {
	k      *KeyRing
	now    time.Time
	claims Claims
}

func newTokenFixture(t *testing.T) *tokenFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewKeyRing("key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	policy := config()
	return &tokenFixture{
		k:   ring,
		now: now,
		claims: Claims{
			TokenProfile:        token.ProfileHumanSessionV1,
			Issuer:              policy.ClusterIssuer,
			Subject:             policy.Issuer + "/user/207",
			Audience:            []string{policy.Audience},
			IssuedAt:            now.Unix(),
			NotBefore:           now.Unix(),
			ExpiresAt:           now.Unix() + policy.TokenSeconds,
			ID:                  "test-token-id",
			Class:               "human",
			GitLabIssuer:        policy.Issuer,
			ProjectID:           policy.ProjectID,
			UserID:              207,
			SessionID:           "test-session-id",
			ApprovedAt:          now.Unix(),
			SessionExp:          now.Unix() + policy.AbsoluteSeconds,
			MembershipCheckedAt: now.Unix(),
			Role:                "admin",
		},
	}
}

func (x *tokenFixture) sign(t *testing.T) string {
	t.Helper()
	raw, err := x.k.Sign(x.claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestVerifyRejectsInvalidClaims(t *testing.T) {
	x := newTokenFixture(t)
	raw := x.sign(t)
	c, err := x.k.Verify(raw, config(), x.now)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Claims)
	}{
		{"wrong cluster issuer", func(c *Claims) { c.Issuer = "wrong" }},
		{"wrong audience", func(c *Claims) { c.Audience = []string{"other"} }},
		{"wrong token class", func(c *Claims) { c.Class = "ci" }},
		{"wrong GitLab issuer", func(c *Claims) { c.GitLabIssuer = "evil" }},
		{"wrong project", func(c *Claims) { c.ProjectID = 702 }},
		{"user ID does not match subject", func(c *Claims) { c.UserID = 208 }},
		{"unknown cluster role", func(c *Claims) { c.Role = "owner" }},
		{"missing issued-at time", func(c *Claims) { c.IssuedAt = 0 }},
		{"missing token ID", func(c *Claims) { c.ID = "" }},
		{"missing not-before time", func(c *Claims) { c.NotBefore = 0 }},
		{"missing session ID", func(c *Claims) { c.SessionID = "" }},
		{"missing approval time", func(c *Claims) { c.ApprovedAt = 0 }},
		{"extended session deadline", func(c *Claims) { c.SessionExp++ }},
		{"missing membership check time", func(c *Claims) { c.MembershipCheckedAt = 0 }},
		{"expiry leaves no session clock-skew budget", func(c *Claims) { c.ExpiresAt = c.SessionExp }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invalidClaims := *c
			tc.mutate(&invalidClaims)
			signed, err := x.k.Sign(invalidClaims)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.k.Verify(signed, config(), x.now); err == nil {
				t.Fatal("accepted invalid claims")
			}
		})
	}
}

func TestSigningKeyRotation(t *testing.T) {
	x := newTokenFixture(t)
	raw := x.sign(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.k.Rotate("key-2", key, x.now); err != nil {
		t.Fatal(err)
	}
	if _, err := x.k.Verify(raw, config(), x.now); err != nil {
		t.Fatal("rotation discarded unexpired old key")
	}
	next := x.sign(t)
	if _, err := x.k.Verify(next, config(), x.now); err != nil {
		t.Fatal("new key invalid")
	}
	if _, err := x.k.Verify(raw, config(), x.now.Add(210*time.Second)); err == nil {
		t.Fatal("old key never retired")
	}
}

func TestRejectAlgorithmKeyAndSignatureConfusion(t *testing.T) {
	x := newTokenFixture(t)
	raw := x.sign(t)
	c, err := x.k.Verify(raw, config(), x.now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	var m jwt.MapClaims
	_ = json.Unmarshal(b, &m)
	for _, algorithm := range []jwt.SigningMethod{jwt.SigningMethodRS256, jwt.SigningMethodHS256, jwt.SigningMethodNone} {
		token := jwt.NewWithClaims(algorithm, m)
		token.Header["kid"] = "key-1"
		token.Header["typ"] = "JWT"
		var key any = x.k.private
		if algorithm == jwt.SigningMethodHS256 {
			key = []byte("synthetic-wrong-key")
		}
		if algorithm == jwt.SigningMethodNone {
			key = jwt.UnsafeAllowNoneSignatureType
		}
		raw, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.k.Verify(raw, config(), x.now); err == nil {
			t.Fatal("accepted algorithm confusion")
		}
	}
	for _, kid := range []string{"", "unknown-key"} {
		token := jwt.NewWithClaims(jwt.SigningMethodPS256, m)
		token.Header["kid"] = kid
		token.Header["typ"] = "JWT"
		raw, err := token.SignedString(x.k.private)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.k.Verify(raw, config(), x.now); err == nil {
			t.Fatal("unknown/missing kid")
		}
	}
	for _, raw := range []string{"", raw + "changed-signature", strings.Repeat("x", 8193)} {
		if _, err := x.k.Verify(raw, config(), x.now); err == nil {
			t.Fatal("invalid signature/encoding accepted")
		}
	}
}

func TestPublishedJWKSVerifiesIssuedToken(t *testing.T) {
	fixture := newTokenFixture(t)
	raw := fixture.sign(t)
	data, err := json.Marshal(fixture.k.JWKS(fixture.now))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Keys) != 1 {
		t.Fatal("expected one signing key")
	}
	key, err := jwkset.NewJWKFromRawJSON(document.Keys[0], jwkset.JWKMarshalOptions{}, jwkset.JWKValidateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := key.Key().(*rsa.PublicKey)
	if !ok {
		t.Fatal("published key is not RSA")
	}
	_, err = Verify(raw, config(), fixture.now, func(id string) (*rsa.PublicKey, error) {
		if id != key.Marshal().KID {
			return nil, ErrDenied
		}
		return publicKey, nil
	})
	if err != nil {
		t.Fatal("published JWK cannot verify issued token:", err)
	}
}

func TestLargeIdentityClaimsRoundTrip(t *testing.T) {
	x := newTokenFixture(t)
	c := config()
	c.ProjectID = 9007199254740993
	x.claims.ProjectID = c.ProjectID
	x.claims.UserID = 9007199254740995
	x.claims.Subject = c.Issuer + "/user/" + decimal(x.claims.UserID)
	raw := x.sign(t)
	claims, err := x.k.Verify(raw, c, x.now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ProjectID != c.ProjectID || claims.UserID != x.claims.UserID {
		t.Fatalf("identity changed: project=%d user=%d", claims.ProjectID, claims.UserID)
	}
}

func TestKeyRingRejectsMissingModulus(t *testing.T) {
	x := newTokenFixture(t)
	raw := x.sign(t)
	for _, tc := range []struct {
		name string
		key  *rsa.PrivateKey
	}{
		{"nil private key", nil},
		{"missing modulus", &rsa.PrivateKey{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewKeyRing("invalid", tc.key); !errors.Is(err, ErrDenied) {
				t.Fatalf("constructor accepted invalid key: %v", err)
			}
			if err := x.k.Rotate("invalid", tc.key, x.now); !errors.Is(err, ErrDenied) {
				t.Fatalf("rotation accepted invalid key: %v", err)
			}
		})
	}
	if _, err := x.k.Verify(raw, config(), x.now); err != nil {
		t.Fatalf("rejected rotation changed the active key: %v", err)
	}
}
