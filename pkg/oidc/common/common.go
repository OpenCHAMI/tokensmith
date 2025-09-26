package common

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openchami/tokensmith/pkg/oidc"
)

// IntrospectToken introspects a token using Remote introspection endpoint
func IntrospectToken(ctx context.Context, keyset jwk.Set, remoteURL, clientID, clientSecret string, token string) (*oidc.IntrospectionResponse, error) {
	// If we have JWKS, try local validation first
	if keyset != nil {
		// Parse the token without verification first to get the key ID
		parser := jwt.Parser{}
		unverifiedToken, _, err := parser.ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			return nil, fmt.Errorf("failed to parse token: %w", err)
		}

		// Find the key with matching kid
		kid, _ := unverifiedToken.Header["kid"].(string)
		var publicKey interface{}
		if key, found := keyset.LookupKeyID(kid); found {
			publicKey, err = key.PublicKey()
			if err != nil {
				return nil, fmt.Errorf("failed to get public key: %w", err)
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

	// Create form data
	formData := fmt.Sprintf("token=%s", token)

	req, err := http.NewRequestWithContext(ctx, "POST", remoteURL, strings.NewReader(formData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

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
