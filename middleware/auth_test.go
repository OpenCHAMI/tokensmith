package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	jwtauth "github.com/openchami/tokensmith/pkg/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockTokenService is a mock implementation of TokenService
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) ExchangeToken(ctx context.Context, token string) (*jwtauth.Claims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwtauth.Claims), args.Error(1)
}

func (m *MockTokenService) GenerateServiceToken(ctx context.Context, scopes []string) (string, error) {
	args := m.Called(ctx, scopes)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) ValidateToken(ctx context.Context, token string) (*jwtauth.Claims, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwtauth.Claims), args.Error(1)
}

func (m *MockTokenService) UpdateGroupScopes(ctx context.Context, group string, scopes []string) error {
	args := m.Called(ctx, group, scopes)
	return args.Error(0)
}

func TestAuthMiddleware(t *testing.T) {
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create test claims
	testClaims := &jwtauth.Claims{
		Issuer:         "test-issuer",
		Subject:        "test-subject",
		Audience:       []string{"test-audience"},
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
		NotBefore:      time.Now().Unix(),
		IssuedAt:       time.Now().Unix(),
		Scope:          []string{"read", "write"},
		ClusterID:      "test-cluster",
		OpenCHAMIID:    "test-openchami-id",
	}

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log claims for debugging
		claims, ok := r.Context().Value(ClaimsContextKey).(*jwtauth.Claims)
		t.Logf("Claims in context: %v", ok)
		if ok {
			t.Logf("Scopes in claims: %v", claims.Scope)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create test token
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, testClaims.Issuer)
	_ = token.Set(jwt.SubjectKey, testClaims.Subject)
	_ = token.Set(jwt.AudienceKey, testClaims.Audience)
	_ = token.Set(jwt.ExpirationKey, time.Unix(testClaims.ExpirationTime, 0))
	_ = token.Set(jwt.NotBeforeKey, time.Unix(testClaims.NotBefore, 0))
	_ = token.Set(jwt.IssuedAtKey, time.Unix(testClaims.IssuedAt, 0))
	_ = token.Set("scope", testClaims.Scope)
	_ = token.Set("cluster_id", testClaims.ClusterID)
	_ = token.Set("openchami_id", testClaims.OpenCHAMIID)

	// Sign the token
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	tokenString := string(tokenBytes)

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
	// Generate a test RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create test claims with scopes
	testClaims := &jwtauth.Claims{
		Issuer:         "test-issuer",
		Subject:        "test-subject",
		Audience:       []string{"test-audience"},
		ExpirationTime: time.Now().Add(time.Hour).Unix(),
		NotBefore:      time.Now().Unix(),
		IssuedAt:       time.Now().Unix(),
		Scope:          []string{"read", "write"},
		ClusterID:      "test-cluster",
		OpenCHAMIID:    "test-openchami-id",
	}

	// Create test handler
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log claims for debugging
		claims, ok := r.Context().Value(ClaimsContextKey).(*jwtauth.Claims)
		t.Logf("Claims in context: %v", ok)
		if ok {
			t.Logf("Scopes in claims: %v", claims.Scope)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Create test token
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, testClaims.Issuer)
	_ = token.Set(jwt.SubjectKey, testClaims.Subject)
	_ = token.Set(jwt.AudienceKey, testClaims.Audience)
	_ = token.Set(jwt.ExpirationKey, time.Unix(testClaims.ExpirationTime, 0))
	_ = token.Set(jwt.NotBeforeKey, time.Unix(testClaims.NotBefore, 0))
	_ = token.Set(jwt.IssuedAtKey, time.Unix(testClaims.IssuedAt, 0))
	_ = token.Set("scope", testClaims.Scope)
	_ = token.Set("cluster_id", testClaims.ClusterID)
	_ = token.Set("openchami_id", testClaims.OpenCHAMIID)

	// Sign the token
	tokenBytes, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privateKey))
	if err != nil {
		t.Fatal(err)
	}
	tokenString := string(tokenBytes)

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
