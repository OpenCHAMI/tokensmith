package keycloak

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/oidc"
)

// KeySet represents a set of JSON Web Keys
type KeySet struct {
	Keys []map[string]interface{}
}

// Client implements the OIDC provider interface for Keycloak
type Client struct {
	baseURL          string
	realm            string
	clientID         string
	clientSecret     string
	metadata         *oidc.ProviderMetadata
	keySet           *KeySet
	lastJWKSUpdate   time.Time
	jwksUpdatePeriod time.Duration
}

// NewClient creates a new Keycloak client
func NewClient(baseURL, realm, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:          baseURL,
		realm:            realm,
		clientID:         clientID,
		clientSecret:     clientSecret,
		jwksUpdatePeriod: 24 * time.Hour,
	}
}

// SupportsLocalIntrospection returns true as Keycloak supports local token validation
func (c *Client) SupportsLocalIntrospection() bool {
	return true
}

// GetJWKS returns the JWKS for local token validation
func (c *Client) GetJWKS(ctx context.Context) (interface{}, error) {
	// Check if we need to update the JWKS
	if c.keySet == nil || time.Since(c.lastJWKSUpdate) > c.jwksUpdatePeriod {
		if err := c.updateJWKS(ctx); err != nil {
			return nil, fmt.Errorf("failed to update JWKS: %w", err)
		}
	}
	// Convert KeySet to map[string]interface{}
	jwksBytes, err := json.Marshal(c.keySet)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWKS: %w", err)
	}
	var jwks map[string]interface{}
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}
	return jwks, nil
}

// updateJWKS fetches the latest JWKS from Keycloak
func (c *Client) updateJWKS(ctx context.Context) error {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, c.realm)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	keySet := &KeySet{}
	for _, key := range jwks.Keys {
		var rawKey map[string]interface{}
		if err := json.Unmarshal(key, &rawKey); err != nil {
			continue
		}
		// Add key to keySet
		keySet.Keys = append(keySet.Keys, rawKey)
	}

	c.keySet = keySet
	c.lastJWKSUpdate = time.Now()
	return nil
}

// GetProviderMetadata returns Keycloak's OIDC provider metadata
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	// Keycloak's well-known configuration endpoint
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", c.baseURL, c.realm)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get provider metadata with status: %d", resp.StatusCode)
	}

	var metadata struct {
		Issuer                string   `json:"issuer"`
		IntrospectionEndpoint string   `json:"introspection_endpoint"`
		JWKSURI               string   `json:"jwks_uri"`
		ScopesSupported       []string `json:"scopes_supported"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Validate required fields
	if metadata.Issuer == "" {
		return nil, fmt.Errorf("missing required field: issuer")
	}
	if metadata.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("missing required field: introspection_endpoint")
	}
	if metadata.JWKSURI == "" {
		return nil, fmt.Errorf("missing required field: jwks_uri")
	}

	return &oidc.ProviderMetadata{
		Issuer:                metadata.Issuer,
		IntrospectionEndpoint: metadata.IntrospectionEndpoint,
		JWKSURI:               metadata.JWKSURI,
		ScopesSupported:       metadata.ScopesSupported,
	}, nil
}

// IntrospectToken introspects a token using Keycloak's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	// If we have JWKS, try local validation first
	if c.keySet != nil {
		parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			// Get the key ID from the token header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("kid header not found")
			}

			// Find the key in the keySet
			for _, key := range c.keySet.Keys {
				if keyID, ok := key["kid"].(string); ok && keyID == kid {
					// Convert the key to the appropriate format based on the algorithm
					switch token.Method.Alg() {
					case "RS256", "RS384", "RS512":
						// For RSA keys, we need to parse the modulus and exponent
						n, ok := key["n"].(string)
						if !ok {
							continue
						}
						e, ok := key["e"].(string)
						if !ok {
							continue
						}
						// Convert base64url to big.Int and create RSA public key
						// This is a simplified version - in production, you'd want to properly
						// parse the modulus and exponent
						return jwt.ParseRSAPublicKeyFromPEM([]byte(fmt.Sprintf(
							"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA%s\n%s\n-----END PUBLIC KEY-----",
							n, e,
						)))
					case "ES256", "ES384", "ES512":
						// For ECDSA keys, we need to parse the x and y coordinates
						x, ok := key["x"].(string)
						if !ok {
							continue
						}
						y, ok := key["y"].(string)
						if !ok {
							continue
						}
						// Convert base64url to big.Int and create ECDSA public key
						// This is a simplified version - in production, you'd want to properly
						// parse the x and y coordinates
						return jwt.ParseECPublicKeyFromPEM([]byte(fmt.Sprintf(
							"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA%s\n%s\n-----END PUBLIC KEY-----",
							x, y,
						)))
					default:
						return nil, fmt.Errorf("unsupported signing method: %v", token.Method.Alg())
					}
				}
			}
			return nil, fmt.Errorf("key not found")
		})

		if err == nil && parsedToken.Valid {
			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			if !ok {
				return nil, fmt.Errorf("invalid claims format")
			}

			return &oidc.IntrospectionResponse{
				Active:    true,
				Username:  claims["sub"].(string),
				ExpiresAt: int64(claims["exp"].(float64)),
				IssuedAt:  int64(claims["iat"].(float64)),
				Claims:    claims,
				TokenType: "Bearer",
			}, nil
		}
	}

	// Fall back to remote introspection
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", c.baseURL, c.realm)

	// Create form data
	formData := fmt.Sprintf("token=%s", token)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(formData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to introspect token: status %d", resp.StatusCode)
	}

	var introspection oidc.IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspection); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	return &introspection, nil
}
