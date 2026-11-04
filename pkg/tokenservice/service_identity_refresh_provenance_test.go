// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestServiceIdentityRefresh_RejectsRevokedPolicyAfterRestart(t *testing.T) {
	// Given: a real mTLS-issued family and a replacement service observing the same durable stores.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "boot-service")
	service := newServiceIdentityPolicyTestService(t, caPEM)
	now := time.Now().UTC()
	policy := serviceIdentityPolicyForHandler(now, "boot-service")
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	logs := useSynchronizedTestLogger(t)
	server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.New(logs)))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	session, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Body.Close()) })
	require.Equal(t, http.StatusOK, session.StatusCode)
	var issued OAuthTokenResponse
	require.NoError(t, json.NewDecoder(session.Body).Decode(&issued))
	family, err := service.refreshTokenStore.GetFamilyByTokenHash(HashBootstrapToken(issued.RefreshToken))
	require.NoError(t, err)
	require.NotNil(t, family.ServiceIdentityPolicy)
	require.Equal(t, policy.ID, family.ServiceIdentityPolicy.PolicyID)
	require.Equal(t, uint64(1), family.ServiceIdentityPolicy.Revision)
	require.NotEmpty(t, family.ServiceIdentityPolicy.Fingerprint)
	data, err := os.ReadFile(filepath.Join(service.refreshTokenStore.storePath, family.FamilyID+".json"))
	require.NoError(t, err)
	require.Contains(t, string(data), "service_identity_policy")
	require.NoError(t, service.serviceIdentityPolicyStore.Revoke(policy.Subject, time.Now().UTC()))
	restarted := newTestTokenService(t, service.Config)

	// When: a process restarted after the policy revocation receives the old refresh token.
	response := httpResponseFor(t, restarted.newRouter(zerolog.New(logs)), refreshRequest(issued.RefreshToken))

	// Then: the policy status is not exposed but the rejection is audited without the credential.
	require.Equal(t, http.StatusBadRequest, response.Code)
	var oauthError OAuthErrorResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&oauthError))
	require.Equal(t, "invalid_grant", oauthError.Error)
	require.Contains(t, logs.String(), "refresh_policy_revoked")
	require.NotContains(t, logs.String(), issued.RefreshToken)
	require.NotContains(t, logs.String(), issued.AccessToken)
}

func TestServiceIdentityRefresh_RejectsSameSubjectPolicyReplacement(t *testing.T) {
	// Given: a real mTLS-issued family bound to a policy instance.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "boot-service")
	service := newServiceIdentityPolicyTestService(t, caPEM)
	policy := serviceIdentityPolicyForHandler(time.Now().UTC(), "boot-service")
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.Nop()))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	session, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Body.Close()) })
	var issued OAuthTokenResponse
	require.NoError(t, json.NewDecoder(session.Body).Decode(&issued))

	// When: the same subject and policy ID are recreated as a new policy instance.
	replacement := *policy
	replacement.CreatedAt = replacement.CreatedAt.Add(time.Minute)
	replacement.ExpiresAt = replacement.ExpiresAt.Add(time.Minute)
	require.NoError(t, service.serviceIdentityPolicyStore.Save(&replacement))
	response := httpResponseFor(t, service.newRouter(zerolog.Nop()), refreshRequest(issued.RefreshToken))

	// Then: subject-only matching cannot keep the old family alive.
	require.Equal(t, http.StatusBadRequest, response.Code)
	var oauthError OAuthErrorResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&oauthError))
	require.Equal(t, "invalid_grant", oauthError.Error)
}

func TestServiceIdentityRefresh_RejectsExternalPolicyRevocationWithoutRestart(t *testing.T) {
	// Given
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "boot-service")
	service := newServiceIdentityPolicyTestService(t, caPEM)
	policy := serviceIdentityPolicyForHandler(time.Now().UTC(), "boot-service")
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.Nop()))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	session, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Body.Close()) })
	var issued OAuthTokenResponse
	require.NoError(t, json.NewDecoder(session.Body).Decode(&issued))

	// When
	revoker := serviceIdentityPolicyProcess(service.Config.ServiceIdentityPolicyStorePath, "revoke")
	require.NoError(t, revoker.Run())
	response := httpResponseFor(t, service.newRouter(zerolog.Nop()), refreshRequest(issued.RefreshToken))

	// Then
	require.Equal(t, http.StatusBadRequest, response.Code)
	var oauthError OAuthErrorResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&oauthError))
	require.Equal(t, "invalid_grant", oauthError.Error)
}

func TestServiceIdentityRefresh_PreservesNilProvenanceBootstrapCompatibilityAfterPolicyRevocation(t *testing.T) {
	// Given: a bootstrap family and an unrelated service identity policy.
	service, bootstrapToken := newRFC8693HandlerTestService(t)
	policy := serviceIdentityPolicyForHandler(time.Now().UTC(), "boot-service")
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	router := service.newRouter(zerolog.Nop())
	issued := httpResponseFor(t, router, bootstrapExchangeRequest(bootstrapToken))
	require.Equal(t, http.StatusOK, issued.Code)
	var bootstrap OAuthTokenResponse
	require.NoError(t, json.NewDecoder(issued.Body).Decode(&bootstrap))
	require.NoError(t, service.serviceIdentityPolicyStore.Revoke(policy.Subject, time.Now().UTC()))

	// When: the bootstrap-derived refresh family is used after that mTLS policy is revoked.
	response := httpResponseFor(t, router, refreshRequest(bootstrap.RefreshToken))

	// Then: nil provenance remains bootstrap-origin compatible.
	require.Equal(t, http.StatusOK, response.Code)
}

func TestServiceIdentityPolicyStore_ValidateRefreshBindingRejectsExpiredPolicy(t *testing.T) {
	// Given
	now := time.Date(2026, time.November, 2, 20, 0, 0, 0, time.UTC)
	store, err := NewServiceIdentityPolicyStore(t.TempDir())
	require.NoError(t, err)
	policy := serviceIdentityPolicyForHandler(now.Add(-time.Hour), "boot-service")
	policy.ExpiresAt = now
	require.NoError(t, store.Save(policy))
	persisted, err := store.GetActive(policy.Subject, now.Add(-time.Nanosecond))
	require.NoError(t, err)
	binding, err := newServiceIdentityPolicyBinding(persisted)
	require.NoError(t, err)

	// When
	err = store.ValidateRefreshBinding(binding, now)

	// Then
	require.ErrorIs(t, err, ErrServiceIdentityPolicyExpired)
}

func httpResponseFor(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
