package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HydraClient defines the interface for Hydra client implementations
type HydraClient interface {
	IntrospectToken(ctx context.Context, token string) (*HydraIntrospectResponse, error)
}

// HydraIntrospectResponse represents the response from Hydra's token introspection endpoint
type HydraIntrospectResponse struct {
	Active   bool                   `json:"active"`
	Scope    string                 `json:"scope,omitempty"`
	ClientID string                 `json:"client_id,omitempty"`
	Username string                 `json:"username,omitempty"`
	Sub      string                 `json:"sub,omitempty"`
	Ext      map[string]interface{} `json:"ext,omitempty"`
	Exp      int64                  `json:"exp,omitempty"`
	Iat      int64                  `json:"iat,omitempty"`
	Nbf      int64                  `json:"nbf,omitempty"`
	Jti      string                 `json:"jti,omitempty"`
	Aud      []string               `json:"aud,omitempty"`
	Iss      string                 `json:"iss,omitempty"`
}

// HydraClientImpl handles communication with Hydra's admin API
type HydraClientImpl struct {
	adminURL string
	client   *http.Client
}

// NewHydraClient creates a new HydraClient instance
func NewHydraClient(adminURL string) HydraClient {
	return &HydraClientImpl{
		adminURL: adminURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IntrospectToken introspects a token with Hydra
func (c *HydraClientImpl) IntrospectToken(ctx context.Context, token string) (*HydraIntrospectResponse, error) {
	// Prepare request body
	body := map[string]string{
		"token": token,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", c.adminURL+"/oauth2/introspect", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse response
	var introspectResp HydraIntrospectResponse
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &introspectResp, nil
}

// CreateInternalToken creates an internal token based on an external token validated by Hydra
func (tm *TokenManager) CreateInternalToken(hydraResp *HydraIntrospectResponse) (string, error) {
	// Convert Hydra scopes to our format
	scopes := make([]string, 0)
	if hydraResp.Scope != "" {
		scopes = append(scopes, hydraResp.Scope)
	}

	claims := &Claims{
		Issuer:         tm.issuer,
		Subject:        hydraResp.Sub,
		Audience:       hydraResp.Aud,
		ExpirationTime: hydraResp.Exp,
		IssuedAt:       hydraResp.Iat,
		Scope:          scopes,
	}

	// Copy any additional claims from Hydra's ext field
	if hydraResp.Ext != nil {
		if name, ok := hydraResp.Ext["name"].(string); ok {
			claims.Name = name
		}
		if email, ok := hydraResp.Ext["email"].(string); ok {
			claims.Email = email
		}
		if emailVerified, ok := hydraResp.Ext["email_verified"].(bool); ok {
			claims.EmailVerified = emailVerified
		}
	}

	return tm.GenerateToken(claims)
}

// HydraMiddleware creates a middleware that validates tokens with Hydra and creates internal tokens
func HydraMiddleware(hydraClient HydraClient, tokenManager *TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			// Check if it's a Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
				return
			}

			// Introspect token with Hydra
			hydraResp, err := hydraClient.IntrospectToken(r.Context(), parts[1])
			if err != nil {
				http.Error(w, "token introspection failed", http.StatusUnauthorized)
				return
			}

			if !hydraResp.Active {
				http.Error(w, "token is not active", http.StatusUnauthorized)
				return
			}

			// Create internal token
			internalToken, err := tokenManager.CreateInternalToken(hydraResp)
			if err != nil {
				http.Error(w, "failed to create internal token", http.StatusInternalServerError)
				return
			}

			// Parse internal token to get claims
			claims, _, err := tokenManager.ParseToken(internalToken)
			if err != nil {
				http.Error(w, "failed to parse internal token", http.StatusInternalServerError)
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
