// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceIdentitySessionHandler_Success(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.SetKeyPair(privateKey, &privateKey.PublicKey))
	caPEM, serviceCert := generateClientIdentityCertificate(t, "boot-service")
	caPath := filepath.Join(t.TempDir(), "service-identity-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	service, err := NewTokenService(keyManager, Config{
		Issuer:                         "http://tokensmith.test",
		ClusterID:                      "cluster-a",
		OpenCHAMIID:                    "openchami-a",
		RFC8693BootstrapStorePath:      filepath.Join(t.TempDir(), "bootstrap-tokens"),
		RFC8693RefreshStorePath:        filepath.Join(t.TempDir(), "refresh-tokens"),
		ServiceIdentityCAPath:          caPath,
		ServiceIdentityPolicyStorePath: filepath.Join(t.TempDir(), "service-identities"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, service.serviceIdentityPolicyStore.Create(serviceIdentityPolicyForHandler(now, "boot-service")))
	req := httptest.NewRequest(http.MethodPost, "/service-identity/session", strings.NewReader("{}"))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{serviceCert}}
	w := httptest.NewRecorder()
	service.ServiceIdentitySessionHandler(w, req)
	resp := w.Result()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var oauthResp OAuthTokenResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&oauthResp))
	require.NotEmpty(t, oauthResp.AccessToken)
	require.NotEmpty(t, oauthResp.RefreshToken)
	assert.Equal(t, "Bearer", oauthResp.TokenType)
	claims, _, err := service.TokenManager.ParseToken(oauthResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "boot-service", claims.Subject)
	assert.Equal(t, []string{"metadata-service"}, []string(claims.Audience))
	assert.Equal(t, []string{"service_identity_mtls"}, claims.AuthMethods)
}

func TestServiceIdentitySessionHandler_RejectsBootstrapPolicyOnly(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.SetKeyPair(privateKey, &privateKey.PublicKey))
	caPEM, serviceCert := generateClientIdentityCertificate(t, "boot-service")
	caPath := filepath.Join(t.TempDir(), "service-identity-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	service, err := NewTokenService(keyManager, Config{
		Issuer:                         "http://tokensmith.test",
		ClusterID:                      "cluster-a",
		OpenCHAMIID:                    "openchami-a",
		RFC8693BootstrapStorePath:      filepath.Join(t.TempDir(), "bootstrap-tokens"),
		RFC8693RefreshStorePath:        filepath.Join(t.TempDir(), "refresh-tokens"),
		ServiceIdentityCAPath:          caPath,
		ServiceIdentityPolicyStorePath: filepath.Join(t.TempDir(), "service-identities"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, service.bootstrapTokenStore.SavePolicy(&BootstrapTokenPolicy{
		ID: "bootstrap-policy", Subject: "boot-service", Audience: "metadata-service", Scopes: []string{"read"}, TokenHash: HashBootstrapToken("placeholder"), TTL: 10 * time.Minute, RefreshTTL: 24 * time.Hour, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}))
	req := httptest.NewRequest(http.MethodPost, "/service-identity/session", strings.NewReader("{}"))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{serviceCert}}
	w := httptest.NewRecorder()
	service.ServiceIdentitySessionHandler(w, req)
	assert.Equal(t, http.StatusForbidden, w.Result().StatusCode)
	var response OAuthErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&response))
	assert.Equal(t, "Service identity authorization failed", response.ErrorDescription)
}

func TestServiceIdentitySessionHandler_TLSAuthorizationStates(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name, certificate string
		policy            func() *ServiceIdentityPolicy
		wantStatus        int
	}{
		{name: "active policy", certificate: "boot-service", policy: func() *ServiceIdentityPolicy { return serviceIdentityPolicyForHandler(now, "boot-service") }, wantStatus: http.StatusOK},
		{name: "wrong certificate subject", certificate: "other-service", policy: func() *ServiceIdentityPolicy { return serviceIdentityPolicyForHandler(now, "boot-service") }, wantStatus: http.StatusForbidden},
		{name: "expired policy", certificate: "boot-service", policy: func() *ServiceIdentityPolicy {
			policy := serviceIdentityPolicyForHandler(now.Add(-2*time.Hour), "boot-service")
			policy.ExpiresAt = now.Add(-time.Hour)
			return policy
		}, wantStatus: http.StatusForbidden},
		{name: "revoked policy", certificate: "boot-service", policy: func() *ServiceIdentityPolicy {
			policy := serviceIdentityPolicyForHandler(now, "boot-service")
			revokedAt := now
			policy.RevokedAt = &revokedAt
			return policy
		}, wantStatus: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, test.certificate)
			service := newServiceIdentityPolicyTestService(t, caPEM)
			require.NoError(t, service.serviceIdentityPolicyStore.Save(test.policy()))
			server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.Nop()))
			certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
			require.NoError(t, err)
			transport := server.Client().Transport.(*http.Transport).Clone()
			transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
			response, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, response.Body.Close()) })
			assert.Equal(t, test.wantStatus, response.StatusCode)
			if test.wantStatus != http.StatusOK {
				var errorResponse OAuthErrorResponse
				require.NoError(t, json.NewDecoder(response.Body).Decode(&errorResponse))
				assert.Equal(t, "Service identity authorization failed", errorResponse.ErrorDescription)
			}
		})
	}
}

func TestServiceIdentitySessionHandler_CapsTokenLifetimesAtPolicyExpiry(t *testing.T) {
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "boot-service")
	service := newServiceIdentityPolicyTestService(t, caPEM)
	now := time.Now().UTC()
	policy := serviceIdentityPolicyForHandler(now, "boot-service")
	policy.RefreshTTL = time.Minute
	policy.ExpiresAt = now.Add(2 * time.Minute)
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.Nop()))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	response, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, response.Body.Close()) })
	require.Equal(t, http.StatusOK, response.StatusCode)
	var session OAuthTokenResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&session))
	claims, _, err := service.TokenManager.ParseToken(session.AccessToken)
	require.NoError(t, err)
	assert.False(t, claims.ExpiresAt.After(policy.ExpiresAt))
	family, err := service.refreshTokenStore.GetFamilyByTokenHash(HashBootstrapToken(session.RefreshToken))
	require.NoError(t, err)
	assert.False(t, family.ExpiresAt.After(policy.ExpiresAt))
}

func newServiceIdentityPolicyTestService(t *testing.T, caPEM []byte) *TokenService {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keyManager := keys.NewKeyManager()
	require.NoError(t, keyManager.SetKeyPair(privateKey, &privateKey.PublicKey))
	caPath := filepath.Join(t.TempDir(), "service-identity-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	service, err := NewTokenService(keyManager, Config{Issuer: "http://tokensmith.test", ClusterID: "cluster-a", OpenCHAMIID: "openchami-a", RFC8693BootstrapStorePath: filepath.Join(t.TempDir(), "bootstrap-tokens"), RFC8693RefreshStorePath: filepath.Join(t.TempDir(), "refresh-tokens"), ServiceIdentityCAPath: caPath, ServiceIdentityPolicyStorePath: filepath.Join(t.TempDir(), "service-identities")})
	require.NoError(t, err)
	return service
}

func serviceIdentityPolicyForHandler(createdAt time.Time, subject string) *ServiceIdentityPolicy {
	return &ServiceIdentityPolicy{Version: ServiceIdentityPolicyVersion, ID: "policy-" + subject, Subject: subject, Audience: "metadata-service", Scopes: []string{"read"}, RefreshTTL: 30 * time.Minute, CreatedAt: createdAt, ExpiresAt: createdAt.Add(time.Hour)}
}
