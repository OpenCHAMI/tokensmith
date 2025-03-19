package keycloak

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

func TestKeycloakClient_IntrospectToken(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		clientID       string
		clientSecret   string
		mockResponse   *oidc.TokenIntrospection
		mockStatusCode int
		expectError    bool
	}{
		{
			name:         "valid token",
			token:        "valid-token",
			clientID:     "test-client",
			clientSecret: "test-secret",
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
			name:         "expired token",
			token:        "expired-token",
			clientID:     "test-client",
			clientSecret: "test-secret",
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
			clientID:       "test-client",
			clientSecret:   "test-secret",
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
				assert.Equal(t, "/realms/test-realm/protocol/openid-connect/token/introspect", r.URL.Path)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				// Parse form data
				err := r.ParseForm()
				assert.NoError(t, err)
				assert.Equal(t, tt.token, r.FormValue("token"))
				assert.Equal(t, tt.clientID, r.FormValue("client_id"))
				assert.Equal(t, tt.clientSecret, r.FormValue("client_secret"))

				// Set response
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			// Create client
			client := NewClient(server.URL, "test-realm", tt.clientID, tt.clientSecret)

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

func TestKeycloakClient_GetProviderMetadata(t *testing.T) {
	tests := []struct {
		name           string
		realm          string
		mockResponse   *oidc.ProviderMetadata
		mockStatusCode int
		expectError    bool
	}{
		{
			name:  "valid metadata",
			realm: "test-realm",
			mockResponse: &oidc.ProviderMetadata{
				Issuer:                "https://keycloak.example.com/realms/test-realm",
				IntrospectionEndpoint: "https://keycloak.example.com/realms/test-realm/protocol/openid-connect/token/introspect",
				JWKSURI:               "https://keycloak.example.com/realms/test-realm/protocol/openid-connect/certs",
				ScopesSupported:       []string{"openid", "profile", "email"},
			},
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error",
			realm:          "test-realm",
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
				assert.Equal(t, "/realms/"+tt.realm+"/.well-known/openid-configuration", r.URL.Path)

				// Set response
				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					json.NewEncoder(w).Encode(tt.mockResponse)
				}
			}))
			defer server.Close()

			// Create client
			client := NewClient(server.URL, tt.realm, "test-client", "test-secret")

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
