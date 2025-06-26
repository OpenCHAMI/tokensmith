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
	"github.com/stretchr/testify/require"
)

func TestKeycloakClient_SupportsLocalIntrospection(t *testing.T) {
	client := NewClient("http://test", "test-realm", "test-client", "test-secret")
	assert.True(t, client.SupportsLocalIntrospection())
}

func TestKeycloakClient_GetJWKS(t *testing.T) {
	tests := []struct {
		name           string
		mockJWKS       string
		mockStatusCode int
		expectError    bool
	}{
		{
			name: "valid JWKS",
			mockJWKS: `{
				"keys": [
					{
						"kty": "RSA",
						"kid": "test-key",
						"use": "sig",
						"n": "test-n",
						"e": "AQAB"
					}
				]
			}`,
			mockStatusCode: http.StatusOK,
			expectError:    false,
		},
		{
			name:           "server error",
			mockJWKS:       "",
			mockStatusCode: http.StatusInternalServerError,
			expectError:    true,
		},
		{
			name:           "invalid JWKS format",
			mockJWKS:       "invalid json",
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/realms/test-realm/protocol/openid-connect/certs", r.URL.Path)
				w.WriteHeader(tt.mockStatusCode)
				w.Write([]byte(tt.mockJWKS))
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-realm", "test-client", "test-secret")
			jwks, err := client.GetJWKS(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, jwks)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jwks)
			}
		})
	}
}

func TestKeycloakClient_IntrospectToken(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		clientID       string
		clientSecret   string
		mockResponse   *oidc.IntrospectionResponse
		mockStatusCode int
		expectError    bool
	}{
		{
			name:         "valid token",
			token:        "valid-token",
			clientID:     "test-client",
			clientSecret: "test-secret",
			mockResponse: &oidc.IntrospectionResponse{
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
			mockResponse: &oidc.IntrospectionResponse{
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
		{
			name:           "invalid response format",
			token:          "invalid-token",
			clientID:       "test-client",
			clientSecret:   "test-secret",
			mockResponse:   nil,
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "POST", r.Method)
				assert.Equal(t, "/realms/test-realm/protocol/openid-connect/token/introspect", r.URL.Path)
				assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

				// Check basic auth
				username, password, ok := r.BasicAuth()
				require.True(t, ok, "Basic auth not provided")
				assert.Equal(t, tt.clientID, username)
				assert.Equal(t, tt.clientSecret, password)

				// Read and parse the request body
				err := r.ParseForm()
				require.NoError(t, err)

				// Verify form values
				assert.Equal(t, tt.token, r.PostForm.Get("token"))

				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					err := json.NewEncoder(w).Encode(tt.mockResponse)
					require.NoError(t, err)
				} else if tt.name == "invalid response format" {
					_, err := w.Write([]byte("invalid json"))
					require.NoError(t, err)
				}
			}))
			defer server.Close()

			client := NewClient(server.URL, "test-realm", tt.clientID, tt.clientSecret)
			result, err := client.IntrospectToken(context.Background(), tt.token)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
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
		{
			name:           "invalid response format",
			realm:          "test-realm",
			mockResponse:   nil,
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
		{
			name:  "missing required fields",
			realm: "test-realm",
			mockResponse: &oidc.ProviderMetadata{
				Issuer: "https://keycloak.example.com/realms/test-realm",
				// Missing other required fields
			},
			mockStatusCode: http.StatusOK,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "/realms/"+tt.realm+"/.well-known/openid-configuration", r.URL.Path)

				w.WriteHeader(tt.mockStatusCode)
				if tt.mockResponse != nil {
					if tt.name == "invalid response format" {
						_, err := w.Write([]byte("invalid json"))
						require.NoError(t, err)
					} else {
						err := json.NewEncoder(w).Encode(tt.mockResponse)
						require.NoError(t, err)
					}
				}
			}))
			defer server.Close()

			client := NewClient(server.URL, tt.realm, "test-client", "test-secret")
			result, err := client.GetProviderMetadata(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, tt.mockResponse.Issuer, result.Issuer)
			assert.Equal(t, tt.mockResponse.IntrospectionEndpoint, result.IntrospectionEndpoint)
			assert.Equal(t, tt.mockResponse.JWKSURI, result.JWKSURI)
			assert.Equal(t, tt.mockResponse.ScopesSupported, result.ScopesSupported)
		})
	}
}
