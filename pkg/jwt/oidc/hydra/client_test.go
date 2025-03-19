package hydra

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

func TestHydraClient_IntrospectToken(t *testing.T) {
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
				assert.Equal(t, "/oauth2/introspect", r.URL.Path)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				// Parse form data
				err := r.ParseForm()
				assert.NoError(t, err)
				assert.Equal(t, tt.token, r.FormValue("token"))

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

func TestHydraClient_GetProviderMetadata(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		validate  func(*testing.T, *oidc.ProviderMetadata)
	}{
		{
			name:      "valid metadata",
			serverURL: "https://hydra.example.com",
			validate: func(t *testing.T, result *oidc.ProviderMetadata) {
				assert.Equal(t, "https://hydra.example.com", result.Issuer)
				assert.Equal(t, "https://hydra.example.com/oauth2/introspect", result.IntrospectionEndpoint)
				assert.Equal(t, "https://hydra.example.com/.well-known/jwks.json", result.JWKSURI)
				assert.Equal(t, []string{"openid", "profile", "email"}, result.ScopesSupported)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := NewClient(tt.serverURL)

			// Test metadata retrieval
			result, err := client.GetProviderMetadata(context.Background())

			// Verify results
			assert.NoError(t, err)
			assert.NotNil(t, result)
			tt.validate(t, result)
		})
	}
}
