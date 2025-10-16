// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockTokenService is a mock implementation of TokenService
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) ExchangeToken(ctx context.Context, idtoken string) (*token.TSClaims, error) {
	args := m.Called(ctx, idtoken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TSClaims), args.Error(1)
}

func (m *MockTokenService) GenerateServiceToken(ctx context.Context, scopes []string) (string, error) {
	args := m.Called(ctx, scopes)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) ValidateToken(ctx context.Context, idtoken string) (*token.TSClaims, error) {
	args := m.Called(ctx, idtoken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.TSClaims), args.Error(1)
}

func (m *MockTokenService) UpdateGroupScopes(ctx context.Context, group string, scopes []string) error {
	args := m.Called(ctx, group, scopes)
	return args.Error(0)
}

func TestAuthMiddleware(t *testing.T) {
	// Create temporary policy model and permission files
	tempDir := t.TempDir()
	modelPath := filepath.Join(tempDir, "model.conf")
	policyPath := filepath.Join(tempDir, "policy.csv")

	modelData := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

	policyData := `
user1, data1, read
user2, data1, write
	`

	if err := os.WriteFile(modelPath, []byte(modelData), 0644); err != nil {
		t.Fatalf("Failed to write model file: %v", err)
	}
	if err := os.WriteFile(policyPath, []byte(policyData), 0644); err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}

	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create test claims
	testClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			Audience:  []string{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Scope:       []string{"read", "write"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami-id",
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"password", "sms"},
		SessionID:   "test-session-123",
		SessionExp:  time.Now().Add(time.Hour).Unix(),
		AuthTime:    time.Now().Unix(),
		AMR:         []string{"pwd", "otp"},
		ACR:         "AAL2",
		AuthEvents:  []string{"login"},
	}

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log claims for debugging
		claims, ok := r.Context().Value(ClaimsContextKey).(*token.TSClaims)
		t.Logf("Claims in context: %v", ok)
		if ok {
			t.Logf("Scopes in claims: %v", claims.Scope)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create test token using Google JWT library
	idtoken := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	tokenString, err := idtoken.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		token          string
		expectedStatus int
		validate       func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "valid token",
			token:          "Bearer " + tokenString,
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, w.Code)
			},
		},
		{
			name:           "missing token",
			token:          "",
			expectedStatus: http.StatusUnauthorized,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), "missing authorization header")
			},
		},
		{
			name:           "invalid token format",
			token:          "invalid-format",
			expectedStatus: http.StatusUnauthorized,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), "invalid authorization header format")
			},
		},
		{
			name:           "invalid token",
			token:          "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
				assert.Contains(t, w.Body.String(), "invalid token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create middleware with validation options
			opts := DefaultMiddlewareOptions()
			opts.ValidateExpiration = true
			opts.ValidateIssuer = true
			opts.ValidateAudience = true
			opts.RequiredClaims = []string{"sub", "iss", "aud"}
			opts.PolicyModelFile = modelPath
			opts.PolicyPermissionsFile = policyPath
			auth := JWTMiddleware(&privateKey.PublicKey, opts)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", tt.token)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call middleware
			handler := auth(testHandler)
			handler.ServeHTTP(w, req)

			// Log response for debugging
			t.Logf("Response Code: %d", w.Code)
			t.Logf("Response Body: %s", w.Body.String())

			// Validate response
			tt.validate(t, w)
		})
	}
}

func TestAuthMiddleware_WithScopes(t *testing.T) {
	// Create temporary policy model and permission files
	tempDir := t.TempDir()
	modelPath := filepath.Join(tempDir, "model.conf")
	policyPath := filepath.Join(tempDir, "policy.csv")

	modelData := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

	policyData := `
user1, data1, read
user2, data1, write
	`

	if err := os.WriteFile(modelPath, []byte(modelData), 0644); err != nil {
		t.Fatalf("Failed to write model file: %v", err)
	}
	if err := os.WriteFile(policyPath, []byte(policyData), 0644); err != nil {
		t.Fatalf("Failed to write policy file: %v", err)
	}

	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create test claims with scopes
	testClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			Audience:  []string{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Scope:       []string{"read", "write"},
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami-id",
		AuthLevel:   "IAL2",
		AuthFactors: 2,
		AuthMethods: []string{"password", "sms"},
		SessionID:   "test-session-123",
		SessionExp:  time.Now().Add(time.Hour).Unix(),
		AuthTime:    time.Now().Unix(),
		AMR:         []string{"pwd", "otp"},
		ACR:         "AAL2",
		AuthEvents:  []string{"login"},
	}

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log claims for debugging
		claims, ok := r.Context().Value(ClaimsContextKey).(*token.TSClaims)
		t.Logf("Claims in context: %v", ok)
		if ok {
			t.Logf("Scopes in claims: %v", claims.Scope)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create test token using Google JWT library
	idtoken := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	tokenString, err := idtoken.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		token          string
		requiredScopes []string
		expectedStatus int
		validate       func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:           "token has required scopes",
			token:          "Bearer " + tokenString,
			requiredScopes: []string{"read"},
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, w.Code)
			},
		},
		{
			name:           "token missing required scopes",
			token:          "Bearer " + tokenString,
			requiredScopes: []string{"admin"},
			expectedStatus: http.StatusForbidden,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusForbidden, w.Code)
				assert.Contains(t, w.Body.String(), "insufficient scope")
			},
		},
		{
			name:           "token has multiple required scopes",
			token:          "Bearer " + tokenString,
			requiredScopes: []string{"read", "write"},
			expectedStatus: http.StatusOK,
			validate: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, w.Code)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create middleware with validation options
			opts := DefaultMiddlewareOptions()
			opts.ValidateExpiration = true
			opts.ValidateIssuer = true
			opts.ValidateAudience = true
			opts.RequiredClaims = []string{"sub", "iss", "aud"}
			opts.PolicyModelFile = modelPath
			opts.PolicyPermissionsFile = policyPath
			auth := JWTMiddleware(&privateKey.PublicKey, opts)

			// Create test request
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", tt.token)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call middleware with required scopes
			handler := auth(RequireScopes(tt.requiredScopes)(testHandler))
			handler.ServeHTTP(w, req)

			// Log response for debugging
			t.Logf("Response Code: %d", w.Code)
			t.Logf("Response Body: %s", w.Body.String())

			// Validate response
			tt.validate(t, w)
		})
	}
}
