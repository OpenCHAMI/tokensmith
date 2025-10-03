// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
)

// FIPS-approved algorithms for JWT signing
const (
	// RSASSA-PSS with SHA-256 (FIPS 186-4)
	DefaultSigningAlgorithm = "PS256"
	// RSASSA-PKCS1-v1_5 with SHA-256 (FIPS 186-4)
	LegacySigningAlgorithm = "RS256"
)

// TokenManager handles JWT token operations
type TokenManager struct {
	keyManager  *keys.KeyManager
	issuer      string
	clusterID   string
	openchamiID string
	algorithm   string
	enforce     bool
}

// NewTokenManager creates a new TokenManager instance
func NewTokenManager(keyManager *keys.KeyManager, issuer string, clusterID string, openchamiID string, enforce bool) *TokenManager {
	return &TokenManager{
		keyManager:  keyManager,
		issuer:      issuer,
		clusterID:   clusterID,
		openchamiID: openchamiID,
		enforce:     enforce,
		algorithm:   DefaultSigningAlgorithm, // Use PS256 by default
	}
}

// SetSigningAlgorithm sets the signing algorithm to use
func (tm *TokenManager) SetSigningAlgorithm(algorithm string) error {
	// Use shared FIPS validation
	if err := keys.ValidateAlgorithm(algorithm); err != nil {
		return err
	}
	tm.algorithm = algorithm
	return nil
}

// GetSigningAlgorithm returns the current signing algorithm
func (tm *TokenManager) GetSigningAlgorithm() string {
	return tm.algorithm
}

// GenerateToken generates a new JWT token with the given claims
func (tm *TokenManager) GenerateToken(claims *TSClaims) (string, error) {
	if claims == nil {
		claims = NewClaims()
		claims.ClusterID = tm.clusterID
		claims.OpenCHAMIID = tm.openchamiID
	}

	// Validate claims
	if err := claims.Validate(tm.enforce); err != nil {
		return "", fmt.Errorf("invalid claims: %w", err)
	}

	// Get private key for signing
	privateKey, err := tm.keyManager.GetPrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %w", err)
	}

	// Generate JTI and nonce
	jti, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}
	nonce, err := generateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Set JTI and nonce in claims
	claims.ID = jti
	claims.Nonce = nonce

	// Get the appropriate signing method for the configured algorithm
	signingMethod, err := keys.GetSigningMethod(tm.algorithm)
	if err != nil {
		return "", fmt.Errorf("invalid signing algorithm: %w", err)
	}

	// Create and sign token using TSClaims directly
	token := jwt.NewWithClaims(signingMethod, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// ExtendedClaims extends TSClaims with additional custom claims
type ExtendedClaims struct {
	*TSClaims
	AdditionalClaims map[string]interface{} `json:"-"`
}

// MarshalJSON implements custom JSON marshaling to include additional claims
func (ec *ExtendedClaims) MarshalJSON() ([]byte, error) {
	// First marshal the base TSClaims
	baseJSON, err := json.Marshal(ec.TSClaims)
	if err != nil {
		return nil, err
	}

	// Parse the base JSON into a map
	var baseMap map[string]interface{}
	if err := json.Unmarshal(baseJSON, &baseMap); err != nil {
		return nil, err
	}

	// Add additional claims
	for key, value := range ec.AdditionalClaims {
		baseMap[key] = value
	}

	// Marshal the combined map
	return json.Marshal(baseMap)
}

// GenerateTokenWithClaims generates a new JWT token with the given claims and additional claims
func (tm *TokenManager) GenerateTokenWithClaims(claims *TSClaims, additionalClaims map[string]interface{}) (string, error) {
	if claims == nil {
		claims = NewClaims()
		claims.ClusterID = tm.clusterID
		claims.OpenCHAMIID = tm.openchamiID
	}

	// Validate claims
	if err := claims.Validate(tm.enforce); err != nil {
		return "", fmt.Errorf("invalid claims: %w", err)
	}

	// Get private key for signing
	privateKey, err := tm.keyManager.GetPrivateKey()
	if err != nil {
		return "", fmt.Errorf("failed to get private key: %w", err)
	}

	// Generate JTI and nonce
	jti, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}
	nonce, err := generateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Set JTI and nonce in claims
	claims.ID = jti
	claims.Nonce = nonce

	// Create extended claims with additional claims
	extendedClaims := &ExtendedClaims{
		TSClaims:         claims,
		AdditionalClaims: additionalClaims,
	}

	// Get the appropriate signing method for the configured algorithm
	signingMethod, err := keys.GetSigningMethod(tm.algorithm)
	if err != nil {
		return "", fmt.Errorf("invalid signing algorithm: %w", err)
	}

	// Create and sign token using ExtendedClaims
	token := jwt.NewWithClaims(signingMethod, extendedClaims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// generateUUID generates a UUID v4
func generateUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Set version to 4 (random)
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant to RFC4122
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// generateNonce generates a random nonce
func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// ParseToken parses a JWT token string into Claims
func (tm *TokenManager) ParseToken(tokenString string) (*TSClaims, map[string]interface{}, error) {
	// Get public key for verification
	publicKey, err := tm.keyManager.GetPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %w", err)
	}

	claims := &TSClaims{}
	// Parse and verify token using custom claims
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("token is invalid")
	}

	// Validate claims using custom logic
	if err := claims.Validate(tm.enforce); err != nil {
		return nil, nil, fmt.Errorf("claims validation failed: %w", err)
	}

	// Convert claims to map[string]interface{} for raw claims
	mapClaims := make(map[string]interface{})
	if m, ok := token.Claims.(jwt.MapClaims); ok {
		for k, v := range m {
			mapClaims[k] = v
		}
	} else {
		// fallback: marshal and unmarshal claims struct to get all fields
		claimsJSON, err := json.Marshal(claims)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal claims: %w", err)
		}
		if err := json.Unmarshal(claimsJSON, &mapClaims); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal claims to map: %w", err)
		}
	}

	return claims, mapClaims, nil
}

// GetKeyManager returns the underlying KeyManager instance
func (tm *TokenManager) GetKeyManager() *keys.KeyManager {
	return tm.keyManager
}

// GenerateServiceToken generates a token for service-to-service communication
func (tm *TokenManager) GenerateServiceToken(serviceID, targetService string, scopes []string) (string, error) {
	now := time.Now()
	claims := &TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   serviceID,
			Audience:  []string{targetService},
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)), // Short-lived tokens for services
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Scope:       scopes,
		ClusterID:   tm.clusterID,
		OpenCHAMIID: tm.openchamiID,
	}

	// Add service-specific claims
	claimsMap := map[string]interface{}{
		"service_id":     serviceID,
		"target_service": targetService,
		"service_scopes": scopes,
	}

	return tm.GenerateTokenWithClaims(claims, claimsMap)
}
