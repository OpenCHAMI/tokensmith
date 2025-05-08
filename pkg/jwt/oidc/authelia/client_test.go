package authelia

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/jwt/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutheliaClient_IntrospectToken(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		mockResponse   *oidc.IntrospectionResponse
		mockStatusCode int
		expectError    bool
	}{
		{
			name:  "valid token",
			token: "valid-token",
			mockResponse: &oidc.IntrospectionResponse{
				Active:    true,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				Claims: map[string]interface{}{
					"scope": "openid profile email",
				},
				TokenType: "Bearer",
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:  "expired token",
			token: "expired-token",
			mockResponse: &oidc.IntrospectionResponse{
				Active:    false,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(-time.Hour).Unix(),
				IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
				Claims: map[string]interface{}{
					"scope": "openid profile email",
				},
				TokenType: "Bearer",
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error",
			token:          "error-token",
			mockResponse:   nil,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/api/oauth2/introspect", r.URL.Path)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				// Verify basic auth
				username, password, ok := r.BasicAuth()
				assert.True(t, ok)
				assert.Equal(t, "test-client-id", username)
				assert.Equal(t, "test-client-secret", password)

				// Verify form data
				err := r.ParseForm()
				require.NoError(t, err)
				assert.Equal(t, tt.token, r.PostForm.Get("token"))

				// Set response
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			// Create client
			client := NewClient(server.URL, "test-client-id", "test-client-secret")

			// Test token introspection
			result, err := client.IntrospectToken(context.Background(), tt.token)

			// Verify results
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.mockResponse.Active, result.Active)
			assert.Equal(t, tt.mockResponse.Username, result.Username)
			assert.Equal(t, tt.mockResponse.ExpiresAt, result.ExpiresAt)
			assert.Equal(t, tt.mockResponse.IssuedAt, result.IssuedAt)
			assert.Equal(t, tt.mockResponse.TokenType, result.TokenType)
			if tt.mockResponse.Claims != nil {
				assert.Equal(t, tt.mockResponse.Claims["scope"], result.Claims["scope"])
			}
		})
	}
}

func TestAutheliaClient_GetProviderMetadata(t *testing.T) {
	tests := []struct {
		name           string
		mockResponse   *oidc.ProviderMetadata
		mockStatusCode int
		expectError    bool
	}{
		{
			name: "valid metadata",
			mockResponse: &oidc.ProviderMetadata{
				Issuer:                "https://authelia.example.com",
				IntrospectionEndpoint: "https://authelia.example.com/api/oauth2/introspect",
				JWKSURI:               "https://authelia.example.com/.well-known/jwks.json",
				ScopesSupported:       []string{"openid", "profile", "email"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error",
			mockResponse:   nil,
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
		{
			name: "missing required fields",
			mockResponse: &oidc.ProviderMetadata{
				Issuer: "https://authelia.example.com",
				// Missing IntrospectionEndpoint and JWKSURI
				ScopesSupported: []string{"openid", "profile", "email"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)

				// Set response
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			// Create client
			client := NewClient(server.URL, "test-client-id", "test-client-secret")

			// Test metadata retrieval
			result, err := client.GetProviderMetadata(context.Background())

			// Verify results
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.mockResponse.Issuer, result.Issuer)
			assert.Equal(t, tt.mockResponse.IntrospectionEndpoint, result.IntrospectionEndpoint)
			assert.Equal(t, tt.mockResponse.JWKSURI, result.JWKSURI)
			assert.Equal(t, tt.mockResponse.ScopesSupported, result.ScopesSupported)
		})
	}
}
