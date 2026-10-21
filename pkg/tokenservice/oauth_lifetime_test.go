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
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestOAuthTokenHandler_FailsClosedBeforeSubsecondBootstrapIssuance(t *testing.T) {
	// Given: a real bootstrap policy whose refresh lifetime cannot be represented safely.
	service, bootstrapToken := newRFC8693HandlerTestService(t)
	policy, err := service.bootstrapTokenStore.GetPolicy(HashBootstrapToken(bootstrapToken))
	require.NoError(t, err)
	policy.RefreshTTL = 500 * time.Millisecond
	require.NoError(t, service.bootstrapTokenStore.UpdatePolicy(policy))
	response := httptest.NewRecorder()

	// When: the production router redeems the bootstrap credential.
	service.newRouter(zerolog.Nop()).ServeHTTP(response, bootstrapExchangeRequest(bootstrapToken))

	// Then: it fails generically before consuming or issuing any credential family.
	require.Equal(t, http.StatusInternalServerError, response.Code)
	var errorResponse OAuthErrorResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&errorResponse))
	require.Equal(t, "server_error", errorResponse.Error)
	policy, err = service.bootstrapTokenStore.GetPolicy(HashBootstrapToken(bootstrapToken))
	require.NoError(t, err)
	require.Nil(t, policy.ConsumedAt)
	entries, err := os.ReadDir(service.Config.RFC8693RefreshStorePath)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestOAuthLifetimeSeconds(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     int
		wantErr  error
	}{
		{name: "positive subsecond", duration: 999 * time.Millisecond, wantErr: ErrOAuthLifetimeTooShort},
		{name: "zero", wantErr: ErrOAuthLifetimeTooShort},
		{name: "negative subsecond", duration: -time.Millisecond, wantErr: ErrOAuthLifetimeTooShort},
		{name: "negative multisecond", duration: -time.Second, wantErr: ErrOAuthLifetimeTooShort},
		{name: "exact second", duration: time.Second, want: 1},
		{name: "fractional second floors", duration: 1900 * time.Millisecond, want: 1},
		{name: "large duration", duration: 72*time.Hour + 900*time.Millisecond, want: 72 * 60 * 60},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := oauthLifetimeSeconds(test.duration)
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, test.want, got)
		})
	}
}

func TestServiceIdentitySessionHandler_FloorsResponseLifetimesWithinPolicyCaps(t *testing.T) {
	// Given: a real mTLS policy with fractional whole-second response bounds.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "boot-service")
	service := newServiceIdentityPolicyTestService(t, caPEM)
	requestStarted := time.Now().UTC()
	policy := serviceIdentityPolicyForHandler(requestStarted, "boot-service")
	policy.ExpiresAt = requestStarted.Add(2500 * time.Millisecond)
	policy.RefreshTTL = 1900 * time.Millisecond
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.Nop()))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}

	// When: the production handler mints an mTLS response.
	response, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, response.Body.Close()) })
	var session OAuthTokenResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&session))

	// Then: advertised lifetimes floor and remain within JWT, family, and policy caps.
	claims, _, err := service.TokenManager.ParseToken(session.AccessToken)
	require.NoError(t, err)
	family, err := service.refreshTokenStore.GetFamilyByTokenHash(HashBootstrapToken(session.RefreshToken))
	require.NoError(t, err)
	require.LessOrEqual(t, time.Duration(session.ExpiresIn)*time.Second, policy.ExpiresAt.Sub(requestStarted))
	require.LessOrEqual(t, time.Duration(session.RefreshExpiresIn)*time.Second, policy.RefreshTTL)
	require.False(t, claims.ExpiresAt.After(policy.ExpiresAt))
	require.False(t, family.ExpiresAt.After(policy.ExpiresAt))
}

func TestServiceIdentitySessionHandler_FailsClosedBeforeSubsecondIssuance(t *testing.T) {
	// Given: an active real mTLS policy with less than one second remaining.
	caPEM, certPath, keyPath := writeServiceIdentityCertFiles(t, "boot-service")
	service := newServiceIdentityPolicyTestService(t, caPEM)
	now := time.Now().UTC()
	policy := serviceIdentityPolicyForHandler(now, "boot-service")
	policy.ExpiresAt = now.Add(500 * time.Millisecond)
	policy.RefreshTTL = 500 * time.Millisecond
	require.NoError(t, service.serviceIdentityPolicyStore.Save(policy))
	server := newServiceIdentityTLSServer(t, caPEM, service.newRouter(zerolog.Nop()))
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}

	// When: the production handler receives the verified client certificate.
	response, err := (&http.Client{Transport: transport}).Post(server.URL+"/service-identity/session", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, response.Body.Close()) })

	// Then: the response is generic and no refresh family is persisted.
	require.Equal(t, http.StatusInternalServerError, response.StatusCode)
	var errorResponse OAuthErrorResponse
	require.NoError(t, json.NewDecoder(response.Body).Decode(&errorResponse))
	require.Equal(t, "server_error", errorResponse.Error)
	entries, err := os.ReadDir(service.Config.RFC8693RefreshStorePath)
	require.NoError(t, err)
	require.Empty(t, entries)
}
