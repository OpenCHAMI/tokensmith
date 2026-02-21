package token

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// helper to create RSA keys for tests
func genRSAKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}
	return k
}

func TestValidateJWT_ValidToken(t *testing.T) {
	priv := genRSAKey(t)
	pub := &priv.PublicKey

	claims := jwt.MapClaims{
		"sub": "user1",
		"iss": "issuer",
		"aud": "audience",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	out, err := ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"test": pub}, AcceptAlgs: []string{"RS256"}})
	if err != nil {
		t.Fatalf("expected valid token, got err: %v", err)
	}
	if out["sub"] != "user1" {
		t.Fatalf("unexpected sub claim: %v", out["sub"])
	}
}

func TestValidateJWT_InvalidSignature(t *testing.T) {
	priv := genRSAKey(t)
	wrong := genRSAKey(t)
	pubWrong := &wrong.PublicKey

	claims := jwt.MapClaims{"sub": "user1", "iss": "issuer", "aud": "audience", "exp": time.Now().Add(5 * time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"test": pubWrong}, AcceptAlgs: []string{"RS256"}})
	if err == nil {
		t.Fatalf("expected signature error")
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	priv := genRSAKey(t)
	pub := &priv.PublicKey

	claims := jwt.MapClaims{"sub": "u", "iss": "i", "aud": "a", "exp": time.Now().Add(-1 * time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k"
	signed, _ := tok.SignedString(priv)

	_, err := ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"k": pub}, AcceptAlgs: []string{"RS256"}})
	if err == nil {
		t.Fatalf("expected expired error")
	}
}

func TestValidateJWT_NotYetValid(t *testing.T) {
	priv := genRSAKey(t)
	pub := &priv.PublicKey

	claims := jwt.MapClaims{"sub": "u", "iss": "i", "aud": "a", "nbf": time.Now().Add(2 * time.Minute).Unix(), "exp": time.Now().Add(10 * time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "k2"
	signed, _ := tok.SignedString(priv)

	_, err := ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"k2": pub}, AcceptAlgs: []string{"RS256"}})
	if err == nil {
		t.Fatalf("expected not-yet-valid error")
	}
}

func TestValidateJWT_WrongAlg(t *testing.T) {
	priv := genRSAKey(t)
	pub := &priv.PublicKey

	claims := jwt.MapClaims{"sub": "u", "iss": "i", "aud": "a", "exp": time.Now().Add(5 * time.Minute).Unix()}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	tok.Header["kid"] = "kid"
	signed, _ := tok.SignedString(priv)

	_, err := ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"kid": pub}, AcceptAlgs: []string{"RS256"}})
	if err == nil {
		t.Fatalf("expected wrong alg error")
	}
}

func TestValidateJWT_ClockSkew(t *testing.T) {
	priv := genRSAKey(t)
	pub := &priv.PublicKey

	// Token expires in 10 seconds
	exp := time.Now().Add(10 * time.Second).Unix()
	claims := jwt.MapClaims{"sub": "u", "iss": "i", "aud": "a", "exp": exp}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "skew"
	signed, _ := tok.SignedString(priv)

	// Validate with 30s skew should accept
	_, err := ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"skew": pub}, AcceptAlgs: []string{"RS256"}, ClockSkew: 30 * time.Second})
	if err != nil {
		t.Fatalf("expected token valid with clock skew, got %v", err)
	}

	// Validate with 0s skew after sleeping until expired
	time.Sleep(11 * time.Second)
	_, err = ValidateJWT(signed, &ValidatorOptions{PublicKeys: map[string]interface{}{"skew": pub}, AcceptAlgs: []string{"RS256"}, ClockSkew: 0})
	if err == nil {
		t.Fatalf("expected expired without skew")
	}
}
