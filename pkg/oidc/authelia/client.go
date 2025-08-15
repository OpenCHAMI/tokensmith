package authelia

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/oidc"
)

// Client implements the OIDC provider interface for Authelia
type Client struct {
	baseURL          string
	clientID         string
	clientSecret     string
	metadata         *oidc.ProviderMetadata
	keySet           *KeySet
	lastJWKSUpdate   time.Time
	jwksUpdatePeriod time.Duration
}

// KeySet represents a set of JSON Web Keys
type KeySet struct {
	Keys []struct {
		Kid string   `json:"kid"`
		Kty string   `json:"kty"`
		Alg string   `json:"alg"`
		Use string   `json:"use"`
		X5c []string `json:"x5c"`
		X5u string   `json:"x5u"`
		Crv string   `json:"crv"`
		X   string   `json:"x"`
		Y   string   `json:"y"`
		E   string   `json:"e"`
		N   string   `json:"n"`
	} `json:"keys"`
}

// NewClient creates a new Authelia client
func NewClient(baseURL, clientID, clientSecret string) *Client {
	return &Client{
		baseURL:          baseURL,
		clientID:         clientID,
		clientSecret:     clientSecret,
		jwksUpdatePeriod: 24 * time.Hour,
	}
}

// SupportsLocalIntrospection returns true as Authelia supports local token validation
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
	return c.keySet, nil
}

// updateJWKS fetches the latest JWKS from Authelia
func (c *Client) updateJWKS(ctx context.Context) error {
	url := fmt.Sprintf("%s/.well-known/jwks.json", c.baseURL)

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

	var keySet KeySet
	if err := json.Unmarshal(body, &keySet); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	c.keySet = &keySet
	c.lastJWKSUpdate = time.Now()
	return nil
}

// IntrospectToken introspects a token using Authelia's introspection endpoint
func (c *Client) IntrospectToken(ctx context.Context, token string) (*oidc.IntrospectionResponse, error) {
	// If we have JWKS, try local validation first
	if c.keySet != nil {
		// Parse the token without verification first to get the key ID
		parser := jwt.Parser{}
		unverifiedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}

		// Find the key with matching kid
		kid, _ := unverifiedToken.Header["kid"].(string)
		var publicKey interface{}
		for _, key := range c.keySet.Keys {
			if key.Kid == kid {
				switch key.Kty {
				case "RSA":
					// Convert RSA key components
					n, err := base64.RawURLEncoding.DecodeString(key.N)
					if err != nil {
						return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
					}
					e, err := base64.RawURLEncoding.DecodeString(key.E)
					if err != nil {
						return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
					}
					publicKey = &rsa.PublicKey{
						N: new(big.Int).SetBytes(n),
						E: int(new(big.Int).SetBytes(e).Int64()),
					}
				case "EC":
					// Convert EC key components
					x, err := base64.RawURLEncoding.DecodeString(key.X)
					if err != nil {
						return nil, fmt.Errorf("failed to decode EC X coordinate: %w", err)
					}
					y, err := base64.RawURLEncoding.DecodeString(key.Y)
					if err != nil {
						return nil, fmt.Errorf("failed to decode EC Y coordinate: %w", err)
					}
					publicKey = &ecdsa.PublicKey{
						X: new(big.Int).SetBytes(x),
						Y: new(big.Int).SetBytes(y),
					}
				}
				break
			}
		}

		if publicKey != nil {
			// Parse and verify the token with the public key
			parsedToken, err := parser.Parse(token, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})
			if err == nil {
				claims, ok := parsedToken.Claims.(jwt.MapClaims)
				if !ok {
					return nil, fmt.Errorf("invalid token claims")
				}

				// Convert claims to map[string]interface{}
				claimsMap := make(map[string]interface{})
				for k, v := range claims {
					claimsMap[k] = v
				}

				return &oidc.IntrospectionResponse{
					Active:    true,
					Username:  claims["sub"].(string),
					ExpiresAt: int64(claims["exp"].(float64)),
					IssuedAt:  int64(claims["iat"].(float64)),
					Claims:    claimsMap,
					TokenType: "Bearer",
				}, nil
			}
		}
	}

	// Fall back to remote introspection
	url := fmt.Sprintf("%s/api/oauth2/introspect", c.baseURL)

	// Create form data
	formData := fmt.Sprintf("token=%s", token)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(formData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
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

// GetProviderMetadata returns Authelia's OIDC provider metadata
func (c *Client) GetProviderMetadata(ctx context.Context) (*oidc.ProviderMetadata, error) {
	url := fmt.Sprintf("%s/.well-known/openid-configuration", c.baseURL)

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
