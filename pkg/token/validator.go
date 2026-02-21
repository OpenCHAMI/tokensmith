package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ValidatorOptions controls how tokens are validated.
type ValidatorOptions struct {
	// PublicKeys maps key IDs (kid) to verification keys (for HMAC it can be []byte)
	PublicKeys map[string]interface{}
	// AcceptAlgs is a whitelist of allowed signing algorithms (e.g. ["HS256","RS256"]).
	AcceptAlgs []string
	// ClockSkew allows leeway when checking exp/nbf
	ClockSkew time.Duration
}

// ValidateJWT verifies signature, algorithm whitelist, and time-based claims with optional clock skew.
// Returns normalized claims as map[string]interface{} or structured errors from pkg/token/errors.go.
func ValidateJWT(tokenString string, opts *ValidatorOptions) (map[string]interface{}, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}
	if opts == nil {
		opts = &ValidatorOptions{}
	}

	claims := jwt.MapClaims{}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		// Algorithm whitelist
		if len(opts.AcceptAlgs) > 0 {
			alg := t.Method.Alg()
			ok := false
			for _, a := range opts.AcceptAlgs {
				if a == alg {
					ok = true
					break
				}
			}
			if !ok {
				return nil, ErrInvalidToken
			}
		}

		// Choose key by kid header
		if len(opts.PublicKeys) > 0 {
			if kidRaw, ok := t.Header["kid"]; ok {
				if kid, ok := kidRaw.(string); ok {
					if k, found := opts.PublicKeys[kid]; found {
						return k, nil
					}
					return nil, ErrInvalidKey
				}
			}
			// No kid provided; if single key present, use it
			if len(opts.PublicKeys) == 1 {
				for _, k := range opts.PublicKeys {
					return k, nil
				}
			}
			return nil, ErrInvalidKey
		}
		return nil, ErrInvalidKey
	}

	parserOpts := []jwt.ParserOption{}
	if len(opts.AcceptAlgs) > 0 {
		parserOpts = append(parserOpts, jwt.WithValidMethods(opts.AcceptAlgs))
	}
	if opts.ClockSkew > 0 {
		parserOpts = append(parserOpts, jwt.WithLeeway(opts.ClockSkew))
	}

	tok, err := jwt.ParseWithClaims(tokenString, &claims, keyFunc, parserOpts...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotValidYet
		}
		// Propagate known token package errors
		if errors.Is(err, ErrInvalidKey) {
			return nil, ErrInvalidKey
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if tok == nil || !tok.Valid {
		return nil, ErrInvalidSignature
	}

	out := make(map[string]interface{})
	for k, v := range claims {
		out[k] = v
	}
	return out, nil
}

// LoadKeyFromEnv is a test helper that returns a byte slice from an environment value.
// It is intentionally small and only for use in unit tests.
func LoadKeyFromEnv(b []byte) interface{} { // trivial helper signature for tests
	return b
}
