// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientInitializeWithOptions(t *testing.T) {
	var receivedGrantType, receivedSubjectToken, receivedSubjectTokenType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		require.NoError(t, r.ParseForm())
		receivedGrantType = r.FormValue("grant_type")
		receivedSubjectToken = r.FormValue("subject_token")
		receivedSubjectTokenType = r.FormValue("subject_token_type")
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt-1",
			TokenType:        "Bearer",
			ExpiresIn:        1800,
			RefreshToken:     "refresh-jwt-1",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"boot-service",
		"boot-service-id",
		"instance-1",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("hsm"),
	)

	err := client.Initialize(context.Background())
	require.NoError(t, err)

	token := client.GetServiceToken()
	require.NotNil(t, token)
	assert.Equal(t, "service-jwt-1", token.Token)
	assert.Equal(t, GrantTypeTokenExchange, receivedGrantType)
	assert.Equal(t, "bootstrap-token", receivedSubjectToken)
	assert.Equal(t, BootstrapTokenTypeRFC8693, receivedSubjectTokenType)

	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.RefreshSuccesses)
	assert.Equal(t, uint64(0), stats.RefreshFailures)
	assert.Equal(t, "", stats.LastError)
	assert.True(t, stats.HasToken)
	assert.True(t, stats.HasRefreshToken)
	assert.False(t, stats.LastSuccess.IsZero())
}

func TestServiceClientInitializeMissingBootstrapToken(t *testing.T) {
	client := NewServiceClientWithOptions(
		"http://tokensmith.local",
		"boot-service",
		"boot-service-id",
		"instance-1",
		"cluster-1",
		WithTargetService("hsm"),
	)

	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingBootstrapToken))
}

func TestServiceClientRefreshTokenIfNeededBoundary(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        600,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(3*time.Minute),
	)

	require.NoError(t, client.GetToken(context.Background()))
	assert.Equal(t, int32(1), calls.Load())

	// Existing token remains valid beyond refresh threshold; no additional exchange.
	require.NoError(t, client.RefreshTokenIfNeeded(context.Background()))
	assert.Equal(t, int32(1), calls.Load())
}

func TestServiceClientRefreshTokenIfNeeded_UsesRefreshGrant(t *testing.T) {
	var calls atomic.Int32
	var grantTypes [2]string
	var tokenValues [2]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		i := int(calls.Add(1)) - 1
		if i < 2 {
			grantTypes[i] = r.FormValue("grant_type")
			if r.FormValue("subject_token") != "" {
				tokenValues[i] = r.FormValue("subject_token")
			} else {
				tokenValues[i] = r.FormValue("refresh_token")
			}
		}

		if calls.Load() == 1 {
			_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
				AccessToken:      "access-1",
				TokenType:        "Bearer",
				ExpiresIn:        1,
				RefreshToken:     "refresh-1",
				RefreshExpiresIn: 3600,
				IssuedTokenType:  AccessTokenTypeRFC8693,
			})
			return
		}

		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "access-2",
			TokenType:        "Bearer",
			ExpiresIn:        600,
			RefreshToken:     "refresh-2",
			RefreshExpiresIn: 3600,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(2*time.Second),
	)

	require.NoError(t, client.Initialize(context.Background()))
	time.Sleep(60 * time.Millisecond)
	require.NoError(t, client.RefreshTokenIfNeeded(context.Background()))

	assert.Equal(t, int32(2), calls.Load())
	assert.Equal(t, GrantTypeTokenExchange, grantTypes[0])
	assert.Equal(t, "bootstrap-token", tokenValues[0])
	assert.Equal(t, GrantTypeRefreshTokenRFC8693, grantTypes[1])
	assert.Equal(t, "refresh-1", tokenValues[1])
}

func TestServiceClientConcurrentRefreshRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        1,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(2*time.Second),
	)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = client.RefreshTokenIfNeeded(context.Background())
		}()
	}
	wg.Wait()

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshSuccesses, uint64(1))
	assert.GreaterOrEqual(t, calls.Load(), int32(1))
}

func TestServiceClientInitializeRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := calls.Add(1)
		if count < 3 {
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}

		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt-after-retry",
			TokenType:        "Bearer",
			ExpiresIn:        1800,
			RefreshToken:     "refresh-jwt-after-retry",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithBootstrapMaxAttempts(5),
		WithBootstrapInitialBackoff(10*time.Millisecond),
		WithBootstrapMaxBackoff(20*time.Millisecond),
	)

	err := client.Initialize(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int32(3), calls.Load())

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshFailures, uint64(2))
	assert.GreaterOrEqual(t, stats.RefreshSuccesses, uint64(1))
	assert.True(t, stats.HasToken)
}

func TestServiceClientInitializeCanceledDuringBackoff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithBootstrapMaxAttempts(5),
		WithBootstrapInitialBackoff(100*time.Millisecond),
		WithBootstrapMaxBackoff(100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := client.Initialize(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bootstrap token exchange canceled")
}

func TestServiceClientRefreshTokenIfNeeded_RefreshTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        1,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 1,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("smd"),
		WithRefreshBefore(200*time.Millisecond),
	)

	require.NoError(t, client.Initialize(context.Background()))
	time.Sleep(1200 * time.Millisecond) // wait for both access and refresh tokens to expire (ExpiresIn: 1s)

	err := client.RefreshTokenIfNeeded(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrRefreshTokenExpired))

	stats := client.Stats()
	assert.GreaterOrEqual(t, stats.RefreshFailures, uint64(1))
	assert.Contains(t, stats.LastError, "refresh token expired")
}

func TestServiceClientStartAutoRefreshStopsOnRefreshTokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "service-jwt",
			TokenType:        "Bearer",
			ExpiresIn:        600,
			RefreshToken:     "refresh-jwt",
			RefreshExpiresIn: 1,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"boot-service",
		"boot-service-id",
		"instance-1",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithTargetService("hsm"),
		WithRefreshBefore(200*time.Millisecond),
		WithAutoRefreshInterval(20*time.Millisecond),
	)

	require.NoError(t, client.Initialize(context.Background()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})

	go func() {
		defer close(done)
		client.StartAutoRefresh(ctx)
	}()

	select {
	case <-done:
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("StartAutoRefresh did not exit after refresh token expiry")
	}
}

func TestServiceClientInitialize_UsesServiceIdentitySessionWhenCertConfigured(t *testing.T) {
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "metadata-service")
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM))

	var serviceIdentityCalls atomic.Int32
	var bootstrapCalls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-identity/session":
			serviceIdentityCalls.Add(1)
			require.NotNil(t, r.TLS)
			require.NotEmpty(t, r.TLS.PeerCertificates)
			_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
				AccessToken:      "mtls-access-token",
				TokenType:        "Bearer",
				ExpiresIn:        1800,
				RefreshToken:     "mtls-refresh-token",
				RefreshExpiresIn: 86400,
				IssuedTokenType:  AccessTokenTypeRFC8693,
			})
		case "/oauth/token":
			bootstrapCalls.Add(1)
			http.Error(w, "bootstrap flow should not be used when mTLS identity is configured", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}
	server.StartTLS()
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-1",
		"cluster-1",
		WithHTTPClient(server.Client()),
		WithServiceIdentityCertKey(certPath, keyPath),
		WithTargetService("smd"),
	)

	require.NoError(t, client.Initialize(context.Background()))
	assert.Equal(t, int32(1), serviceIdentityCalls.Load())
	assert.Equal(t, int32(0), bootstrapCalls.Load())
}

func TestServiceClientInitialize_FallsBackToBootstrapWhenServiceIdentityFilesUnreadable(t *testing.T) {
	var bootstrapCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/oauth/token", r.URL.Path)
		bootstrapCalls.Add(1)
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{
			AccessToken:      "bootstrap-access-token",
			TokenType:        "Bearer",
			ExpiresIn:        1800,
			RefreshToken:     "bootstrap-refresh-token",
			RefreshExpiresIn: 86400,
			IssuedTokenType:  AccessTokenTypeRFC8693,
		})
	}))
	defer server.Close()

	client := NewServiceClientWithOptions(
		server.URL,
		"metadata-service",
		"metadata-service-id",
		"instance-2",
		"cluster-1",
		WithBootstrapToken("bootstrap-token"),
		WithServiceIdentityCertKey("/does/not/exist.crt", "/does/not/exist.key"),
		WithTargetService("smd"),
	)

	require.NoError(t, client.Initialize(context.Background()))
	assert.Equal(t, int32(1), bootstrapCalls.Load())
}

func TestServiceClientInitialize_FailsWhenOnlyOneServiceIdentityPathProvided(t *testing.T) {
	client := NewServiceClientWithOptions(
		"http://tokensmith.local",
		"metadata-service",
		"metadata-service-id",
		"instance-3",
		"cluster-1",
		WithServiceIdentityCertKey("/tmp/service.crt", ""),
		WithTargetService("smd"),
	)

	err := client.Initialize(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTLSClientMaterial)
}

func writeServiceIdentityCertFiles(t *testing.T, subjectCN string) ([]byte, string, string) {
	t.Helper()

	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "tokensmith-test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName:   subjectCN,
			Organization: []string{"openchami"},
		},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "service.crt")
	keyPath := filepath.Join(tempDir, "service.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return caPEM, certPath, keyPath
}
