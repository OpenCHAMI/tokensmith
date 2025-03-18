package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenManager handles JWT token operations
type TokenManager struct {
	keyManager  *KeyManager
	issuer      string
	clusterID   string
	openchamiID string
}

// NewTokenManager creates a new TokenManager instance
func NewTokenManager(keyManager *KeyManager, issuer string, clusterID string, openchamiID string) *TokenManager {
	return &TokenManager{
		keyManager:  keyManager,
		issuer:      issuer,
		clusterID:   clusterID,
		openchamiID: openchamiID,
	}
}

// GenerateToken generates a new JWT token with the given claims
func (tm *TokenManager) GenerateToken(claims *Claims) (string, error) {
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

	// Create token
	token := jwt.New()

	// Set standard claims
	if err := token.Set(jwt.IssuerKey, claims.Issuer); err != nil {
		return "", fmt.Errorf("failed to set issuer: %w", err)
	}
	if err := token.Set(jwt.SubjectKey, claims.Subject); err != nil {
		return "", fmt.Errorf("failed to set subject: %w", err)
	}
	if err := token.Set(jwt.AudienceKey, claims.Audience); err != nil {
		return "", fmt.Errorf("failed to set audience: %w", err)
	}
	if err := token.Set(jwt.ExpirationKey, claims.ExpirationTime); err != nil {
		return "", fmt.Errorf("failed to set expiration: %w", err)
	}
	if err := token.Set(jwt.NotBeforeKey, claims.NotBefore); err != nil {
		return "", fmt.Errorf("failed to set not before: %w", err)
	}
	if err := token.Set(jwt.IssuedAtKey, claims.IssuedAt); err != nil {
		return "", fmt.Errorf("failed to set issued at: %w", err)
	}

	// Add JTI (JWT ID) to prevent replay attacks
	jti, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}
	if err := token.Set(jwt.JwtIDKey, jti); err != nil {
		return "", fmt.Errorf("failed to set JTI: %w", err)
	}

	// Add nonce for additional replay protection
	nonce, err := generateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	if err := token.Set("nonce", nonce); err != nil {
		return "", fmt.Errorf("failed to set nonce: %w", err)
	}

	// Set custom claims
	if claims.Scope != nil {
		if err := token.Set("scope", claims.Scope); err != nil {
			return "", fmt.Errorf("failed to set scope: %w", err)
		}
	}
	if claims.Name != "" {
		if err := token.Set("name", claims.Name); err != nil {
			return "", fmt.Errorf("failed to set name: %w", err)
		}
	}
	if claims.Email != "" {
		if err := token.Set("email", claims.Email); err != nil {
			return "", fmt.Errorf("failed to set email: %w", err)
		}
	}
	if err := token.Set("email_verified", claims.EmailVerified); err != nil {
		return "", fmt.Errorf("failed to set email_verified: %w", err)
	}

	// Marshal token to JSON
	payload, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// Sign token
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

// GenerateTokenWithClaims generates a new JWT token with the given claims and additional claims
func (tm *TokenManager) GenerateTokenWithClaims(claims *Claims, additionalClaims map[string]interface{}) (string, error) {
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

	// Create token
	token := jwt.New()

	// Set standard claims
	if err := token.Set(jwt.IssuerKey, claims.Issuer); err != nil {
		return "", fmt.Errorf("failed to set issuer: %w", err)
	}
	if err := token.Set(jwt.SubjectKey, claims.Subject); err != nil {
		return "", fmt.Errorf("failed to set subject: %w", err)
	}
	if err := token.Set(jwt.AudienceKey, claims.Audience); err != nil {
		return "", fmt.Errorf("failed to set audience: %w", err)
	}
	if err := token.Set(jwt.ExpirationKey, claims.ExpirationTime); err != nil {
		return "", fmt.Errorf("failed to set expiration: %w", err)
	}
	if err := token.Set(jwt.NotBeforeKey, claims.NotBefore); err != nil {
		return "", fmt.Errorf("failed to set not before: %w", err)
	}
	if err := token.Set(jwt.IssuedAtKey, claims.IssuedAt); err != nil {
		return "", fmt.Errorf("failed to set issued at: %w", err)
	}

	// Add JTI (JWT ID) to prevent replay attacks
	jti, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}
	if err := token.Set(jwt.JwtIDKey, jti); err != nil {
		return "", fmt.Errorf("failed to set JTI: %w", err)
	}

	// Add nonce for additional replay protection
	nonce, err := generateNonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	if err := token.Set("nonce", nonce); err != nil {
		return "", fmt.Errorf("failed to set nonce: %w", err)
	}

	// Set custom claims
	if claims.Scope != nil {
		if err := token.Set("scope", claims.Scope); err != nil {
			return "", fmt.Errorf("failed to set scope: %w", err)
		}
	}
	if claims.Name != "" {
		if err := token.Set("name", claims.Name); err != nil {
			return "", fmt.Errorf("failed to set name: %w", err)
		}
	}
	if claims.Email != "" {
		if err := token.Set("email", claims.Email); err != nil {
			return "", fmt.Errorf("failed to set email: %w", err)
		}
	}
	if err := token.Set("email_verified", claims.EmailVerified); err != nil {
		return "", fmt.Errorf("failed to set email_verified: %w", err)
	}

	// Set additional claims
	for key, value := range additionalClaims {
		if err := token.Set(key, value); err != nil {
			return "", fmt.Errorf("failed to set additional claim %s: %w", key, err)
		}
	}

	// Marshal token to JSON
	payload, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	// Sign token
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256, privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
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
func (tm *TokenManager) ParseToken(tokenString string) (*Claims, map[string]interface{}, error) {
	// Get public key for verification
	publicKey, err := tm.keyManager.GetPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse and verify token
	token, err := jwt.ParseString(tokenString, jwt.WithKey(jwa.RS256, publicKey))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims := &Claims{
		Issuer:         token.Issuer(),
		Subject:        token.Subject(),
		Audience:       token.Audience(),
		ExpirationTime: token.Expiration().Unix(),
		NotBefore:      token.NotBefore().Unix(),
		IssuedAt:       token.IssuedAt().Unix(),
		JTI:            token.JwtID(),
		ClusterID:      token.PrivateClaims()["cluster_id"].(string),
		OpenCHAMIID:    token.PrivateClaims()["openchami_id"].(string),
	}

	// Extract custom claims
	if scope, ok := token.PrivateClaims()["scope"].([]interface{}); ok {
		claims.Scope = make([]string, len(scope))
		for i, v := range scope {
			if s, ok := v.(string); ok {
				claims.Scope[i] = s
			}
		}
	}
	if name, ok := token.PrivateClaims()["name"].(string); ok {
		claims.Name = name
	}
	if email, ok := token.PrivateClaims()["email"].(string); ok {
		claims.Email = email
	}
	if emailVerified, ok := token.PrivateClaims()["email_verified"].(bool); ok {
		claims.EmailVerified = emailVerified
	}
	if nonce, ok := token.PrivateClaims()["nonce"].(string); ok {
		claims.Nonce = nonce
	}

	return claims, token.PrivateClaims(), nil
}

// GetKeyManager returns the underlying KeyManager instance
func (tm *TokenManager) GetKeyManager() *KeyManager {
	return tm.keyManager
}

// GenerateServiceToken generates a token for service-to-service communication
func (tm *TokenManager) GenerateServiceToken(serviceID, targetService string, scopes []string) (string, error) {
	now := time.Now()
	claims := &Claims{
		Issuer:         tm.issuer,
		Subject:        serviceID,
		Audience:       []string{targetService},
		ExpirationTime: now.Add(5 * time.Minute).Unix(), // Short-lived tokens for services
		NotBefore:      now.Unix(),
		IssuedAt:       now.Unix(),
		Scope:          scopes,
		ClusterID:      tm.clusterID,
		OpenCHAMIID:    tm.openchamiID,
	}

	// Add service-specific claims
	claimsMap := map[string]interface{}{
		"service_id":     serviceID,
		"target_service": targetService,
		"service_scopes": scopes,
	}

	return tm.GenerateTokenWithClaims(claims, claimsMap)
}
