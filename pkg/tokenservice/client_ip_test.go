// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestRequestClientIP_usesDirectPeer_whenForwardedHeadersArePresent(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{name: "ipv4 host and port", remoteAddr: "198.51.100.25:1234", want: "198.51.100.25"},
		{name: "ipv6 host and port", remoteAddr: "[2001:db8::25]:1234", want: "2001:db8::25"},
		{name: "malformed remote address", remoteAddr: "malformed-peer", want: "malformed-peer"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var gotClientIP string
			var gotExchangeClientIP string
			var gotRemoteAddr string
			handler := middleware.ClientIPFromRemoteAddr(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				gotClientIP = requestClientIP(r)
				gotExchangeClientIP = exchangeClientIP(r)
				gotRemoteAddr = r.RemoteAddr
			}))
			request := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("True-Client-IP", "203.0.113.10")
			request.Header.Set("X-Real-IP", "203.0.113.11")
			request.Header.Add("X-Forwarded-For", "malformed-client")
			request.Header.Add("X-Forwarded-For", "203.0.113.12, 10.0.0.1")

			// When
			handler.ServeHTTP(httptest.NewRecorder(), request)

			// Then
			require.Equal(t, test.want, gotClientIP)
			require.Equal(t, test.want, gotExchangeClientIP)
			require.Equal(t, test.remoteAddr, gotRemoteAddr)
		})
	}
}

func TestOAuthTokenHandler_recordsSocketPeerForBootstrapAudit_whenForwardedHeadersAreSpoofed(t *testing.T) {
	// Given
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.Nop())
	request := bootstrapExchangeRequest(bootstrapToken)
	request.RemoteAddr = "[2001:db8::25]:1234"
	request.Header.Set("True-Client-IP", "203.0.113.10")
	request.Header.Set("X-Real-IP", "203.0.113.11")
	request.Header.Add("X-Forwarded-For", "malformed-client")
	request.Header.Add("X-Forwarded-For", "203.0.113.12, 10.0.0.1")

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	// Then
	require.Equal(t, http.StatusOK, response.Code)
	policy, err := svc.bootstrapTokenStore.GetPolicy(HashBootstrapToken(bootstrapToken))
	require.NoError(t, err)
	require.Equal(t, "2001:db8::25", policy.ConsumedByIP)
}

func TestOAuthTokenHandler_rateLimitsSocketPeer_whenForwardedHeadersAreSpoofed(t *testing.T) {
	// Given
	svc, _ := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.Nop())
	const socketPeer = "198.51.100.25:1234"

	// When
	for attempt := range replayMaxAttempts {
		response := httptest.NewRecorder()
		request := bootstrapExchangeRequest(fmt.Sprintf("spoofed-bootstrap-%d", attempt))
		request.RemoteAddr = socketPeer
		request.Header.Set("True-Client-IP", fmt.Sprintf("203.0.113.%d", attempt))
		request.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", attempt))
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d, 10.0.0.1", attempt))
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusBadRequest, response.Code)
	}
	blocked := httptest.NewRecorder()
	blockedRequest := bootstrapExchangeRequest("spoofed-bootstrap-blocked")
	blockedRequest.RemoteAddr = socketPeer
	blockedRequest.Header.Set("X-Forwarded-For", "203.0.113.250, 10.0.0.1")
	router.ServeHTTP(blocked, blockedRequest)

	// Then
	require.Equal(t, http.StatusTooManyRequests, blocked.Code)
}

func TestClientIPDriver_usesSocketPeerForBootstrapAudit_whenHeadersAreSpoofed(t *testing.T) {
	// Given
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	server := httptest.NewServer(svc.newRouter(zerolog.Nop()))
	defer server.Close()
	form := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {bootstrapToken},
		"subject_token_type": {BootstrapTokenTypeRFC8693},
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/oauth/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("True-Client-IP", "203.0.113.10")
	request.Header.Set("X-Real-IP", "203.0.113.11")
	request.Header.Add("X-Forwarded-For", "malformed-client")
	request.Header.Add("X-Forwarded-For", "203.0.113.12, 10.0.0.1")

	// When
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, response.Body.Close()) })

	// Then
	require.Equal(t, http.StatusOK, response.StatusCode)
	policy, err := svc.bootstrapTokenStore.GetPolicy(HashBootstrapToken(bootstrapToken))
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", policy.ConsumedByIP)
}

func TestClientIPDriver_rateLimitsSocketPeer_whenHeadersAreSpoofed(t *testing.T) {
	// Given
	svc, _ := newRFC8693HandlerTestService(t)
	server := httptest.NewServer(svc.newRouter(zerolog.Nop()))
	defer server.Close()

	// When
	var statusCode int
	for attempt := range replayMaxAttempts + 1 {
		form := url.Values{
			"grant_type":         {GrantTypeTokenExchange},
			"subject_token":      {fmt.Sprintf("spoofed-bootstrap-%d", attempt)},
			"subject_token_type": {BootstrapTokenTypeRFC8693},
		}
		request, err := http.NewRequest(http.MethodPost, server.URL+"/oauth/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("True-Client-IP", fmt.Sprintf("203.0.113.%d", attempt))
		request.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", attempt))
		request.Header.Add("X-Forwarded-For", fmt.Sprintf("malformed-client-%d", attempt))
		request.Header.Add("X-Forwarded-For", fmt.Sprintf("203.0.113.%d, 10.0.0.1", attempt))

		response, err := server.Client().Do(request)
		require.NoError(t, err)
		statusCode = response.StatusCode
		require.NoError(t, response.Body.Close())
	}

	// Then
	require.Equal(t, http.StatusTooManyRequests, statusCode)
}
