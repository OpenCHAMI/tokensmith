package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	keyManager  *KeyManager
	issuer      string
	clusterID   string
	openchamiID string
	algorithm   string
}

// NewTokenManager creates a new TokenManager instance
func NewTokenManager(keyManager *KeyManager, issuer string, clusterID string, openchamiID string) *TokenManager {
	return &TokenManager{
		keyManager:  keyManager,
		issuer:      issuer,
		clusterID:   clusterID,
		openchamiID: openchamiID,
		algorithm:   DefaultSigningAlgorithm, // Use PS256 by default
	}
}

// SetSigningAlgorithm sets the signing algorithm to use
func (tm *TokenManager) SetSigningAlgorithm(algorithm string) error {
	// Only allow FIPS-approved algorithms
	switch algorithm {
	case "PS256", "PS384", "PS512", // RSASSA-PSS
		"RS256", "RS384", "RS512", // RSASSA-PKCS1-v1_5
		"ES256", "ES384", "ES512": // ECDSA
		tm.algorithm = algorithm
		return nil
	default:
		return fmt.Errorf("algorithm %s is not FIPS-approved", algorithm)
	}
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
	if err := claims.Validate(); err != nil {
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

	// Create token claims
	tokenClaims := jwt.MapClaims{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.Audience,
		"exp":   claims.ExpiresAt,
		"nbf":   claims.NotBefore,
		"iat":   claims.IssuedAt,
		"jti":   jti,
		"nonce": nonce,
	}

	// Add OpenID Connect claims
	if claims.Name != "" {
		tokenClaims["name"] = claims.Name
	}
	if claims.Email != "" {
		tokenClaims["email"] = claims.Email
	}
	tokenClaims["email_verified"] = claims.EmailVerified
	if claims.AuthTime != 0 {
		tokenClaims["auth_time"] = claims.AuthTime
	}
	if len(claims.AMR) > 0 {
		tokenClaims["amr"] = claims.AMR
	}
	if claims.ACR != "" {
		tokenClaims["acr"] = claims.ACR
	}

	// Add NIST-compliant claims
	tokenClaims["auth_level"] = claims.AuthLevel
	tokenClaims["auth_factors"] = claims.AuthFactors
	tokenClaims["auth_methods"] = claims.AuthMethods
	tokenClaims["session_id"] = claims.SessionID
	tokenClaims["session_exp"] = claims.SessionExp
	if len(claims.AuthEvents) > 0 {
		tokenClaims["auth_events"] = claims.AuthEvents
	}

	// Add OpenCHAMI specific claims
	if claims.Scope != nil {
		tokenClaims["scope"] = claims.Scope
	}
	if claims.ClusterID != "" {
		tokenClaims["cluster_id"] = claims.ClusterID
	}
	if claims.OpenCHAMIID != "" {
		tokenClaims["openchami_id"] = claims.OpenCHAMIID
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signed, nil
}

// GenerateTokenWithClaims generates a new JWT token with the given claims and additional claims
func (tm *TokenManager) GenerateTokenWithClaims(claims *TSClaims, additionalClaims map[string]interface{}) (string, error) {
	if claims == nil {
		claims = NewClaims()
		claims.ClusterID = tm.clusterID
		claims.OpenCHAMIID = tm.openchamiID
	}

	// Validate claims
	if err := claims.Validate(); err != nil {
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

	// Create token claims
	tokenClaims := jwt.MapClaims{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.Audience,
		"exp":   claims.ExpiresAt,
		"nbf":   claims.NotBefore,
		"iat":   claims.IssuedAt,
		"jti":   jti,
		"nonce": nonce,
	}

	// Add OpenID Connect claims
	if claims.Name != "" {
		tokenClaims["name"] = claims.Name
	}
	if claims.Email != "" {
		tokenClaims["email"] = claims.Email
	}
	tokenClaims["email_verified"] = claims.EmailVerified
	if claims.AuthTime != 0 {
		tokenClaims["auth_time"] = claims.AuthTime
	}
	if len(claims.AMR) > 0 {
		tokenClaims["amr"] = claims.AMR
	}
	if claims.ACR != "" {
		tokenClaims["acr"] = claims.ACR
	}

	// Add NIST-compliant claims
	tokenClaims["auth_level"] = claims.AuthLevel
	tokenClaims["auth_factors"] = claims.AuthFactors
	tokenClaims["auth_methods"] = claims.AuthMethods
	tokenClaims["session_id"] = claims.SessionID
	tokenClaims["session_exp"] = claims.SessionExp
	if len(claims.AuthEvents) > 0 {
		tokenClaims["auth_events"] = claims.AuthEvents
	}

	// Add OpenCHAMI specific claims
	if claims.Scope != nil {
		tokenClaims["scope"] = claims.Scope
	}
	if claims.ClusterID != "" {
		tokenClaims["cluster_id"] = claims.ClusterID
	}
	if claims.OpenCHAMIID != "" {
		tokenClaims["openchami_id"] = claims.OpenCHAMIID
	}

	// Add additional claims
	for key, value := range additionalClaims {
		tokenClaims[key] = value
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
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
	if err := claims.Validate(); err != nil {
		return nil, nil, fmt.Errorf("claims validation failed: %w", err)
	}

	// Convert claims to map[string]interface{} for raw claims
	mapClaims := make(map[string]interface{})
	if m, ok := token.Claims.(jwt.MapClaims); ok {
		for k, v := range m {
			mapClaims[k] = v
		}
	} else {
		// fallback: marshal and unmarshal claims struct
		// (optional, can be omitted if not needed)
	}

	return claims, mapClaims, nil
}

// GetKeyManager returns the underlying KeyManager instance
func (tm *TokenManager) GetKeyManager() *KeyManager {
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

// GetIssuer returns the issuer configured for this token manager
func (tm *TokenManager) GetIssuer() string {
	return tm.issuer
}
