package jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// FIPS-approved algorithms for JWT signing
// These algorithms are approved by FIPS 186-4 and FIPS 140-2/140-3
var FIPSApprovedAlgorithms = map[string]bool{
	"PS256": true, "PS384": true, "PS512": true, // RSASSA-PSS
	"RS256": true, "RS384": true, "RS512": true, // RSASSA-PKCS1-v1_5
	"ES256": true, "ES384": true, "ES512": true, // ECDSA
}

// ValidateAlgorithm checks if the algorithm is FIPS-approved
func ValidateAlgorithm(alg string) error {
	if !FIPSApprovedAlgorithms[alg] {
		return fmt.Errorf("algorithm %s is not FIPS-approved. Approved algorithms: PS256, PS384, PS512, RS256, RS384, RS512, ES256, ES384, ES512", alg)
	}
	return nil
}

// GetSigningMethod returns the appropriate signing method for the algorithm
func GetSigningMethod(alg string) (jwt.SigningMethod, error) {
	if err := ValidateAlgorithm(alg); err != nil {
		return nil, err
	}

	switch alg {
	case "PS256":
		return jwt.SigningMethodPS256, nil
	case "PS384":
		return jwt.SigningMethodPS384, nil
	case "PS512":
		return jwt.SigningMethodPS512, nil
	case "RS256":
		return jwt.SigningMethodRS256, nil
	case "RS384":
		return jwt.SigningMethodRS384, nil
	case "RS512":
		return jwt.SigningMethodRS512, nil
	case "ES256":
		return jwt.SigningMethodES256, nil
	case "ES384":
		return jwt.SigningMethodES384, nil
	case "ES512":
		return jwt.SigningMethodES512, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// GetFIPSApprovedAlgorithms returns a list of all FIPS-approved algorithms
func GetFIPSApprovedAlgorithms() []string {
	algorithms := make([]string, 0, len(FIPSApprovedAlgorithms))
	for alg := range FIPSApprovedAlgorithms {
		algorithms = append(algorithms, alg)
	}
	return algorithms
}
