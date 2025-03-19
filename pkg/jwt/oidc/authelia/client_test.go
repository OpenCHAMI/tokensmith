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
)

func TestAutheliaClient_IntrospectToken(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		mockResponse   *oidc.TokenIntrospection
		mockStatusCode int
		expectError    bool
	}{
		{
			name:  "valid token",
			token: "valid-token",
			mockResponse: &oidc.TokenIntrospection{
				Active:    true,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				IssuedAt:  time.Now().Unix(),
				Scope:     "openid profile email",
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:  "expired token",
			token: "expired-token",
			mockResponse: &oidc.TokenIntrospection{
				Active:    false,
				Username:  "testuser",
				ExpiresAt: time.Now().Add(-time.Hour).Unix(),
				IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
				Scope:     "openid profile email",
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
				assert.Equal(t, "/api/verify", r.URL.Path)
				assert.Equal(t, "Bearer "+tt.token, r.Header.Get("Authorization"))
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				// Set response
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			// Create client
			client := NewClient(server.URL)

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
			assert.Equal(t, tt.mockResponse.Scope, result.Scope)
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
				IntrospectionEndpoint: "https://authelia.example.com/api/verify",
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
			client := NewClient(server.URL)

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
