// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestOAuthTokenHandler_bootstrap_exchange_consumes_once_concurrently(t *testing.T) {
	// Given
	logs := useSynchronizedTestLogger(t)
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(logs))
	start := make(chan struct{})
	statuses := make(chan int, 20)
	var workers sync.WaitGroup

	// When
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			response := httptest.NewRecorder()
			router.ServeHTTP(response, bootstrapExchangeRequest(bootstrapToken))
			statuses <- response.Code
		}()
	}
	close(start)
	workers.Wait()
	close(statuses)

	// Then
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
			continue
		}
		require.Contains(t, []int{http.StatusBadRequest, http.StatusTooManyRequests}, status)
	}
	require.Equal(t, 1, successes)
}

func TestOAuthTokenHandler_unknown_bootstrap_tokens_are_rate_limited_by_client_IP(t *testing.T) {
	// Given
	logs := useSynchronizedTestLogger(t)
	svc, bootstrapToken := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(logs))
	const unknownClientIP = "198.51.100.25:1234"

	// When
	for attempt := range replayMaxAttempts {
		response := httptest.NewRecorder()
		request := bootstrapExchangeRequest(fmt.Sprintf("unknown-bootstrap-%d", attempt))
		request.RemoteAddr = unknownClientIP
		router.ServeHTTP(response, request)
		require.Equal(t, http.StatusBadRequest, response.Code)
	}
	blocked := httptest.NewRecorder()
	blockedRequest := bootstrapExchangeRequest("unknown-bootstrap-blocked")
	blockedRequest.RemoteAddr = unknownClientIP
	router.ServeHTTP(blocked, blockedRequest)
	unknownLogs := logs.String()
	valid := httptest.NewRecorder()
	validRequest := bootstrapExchangeRequest(bootstrapToken)
	validRequest.RemoteAddr = "203.0.113.25:1234"
	router.ServeHTTP(valid, validRequest)

	// Then
	require.Equal(t, http.StatusTooManyRequests, blocked.Code)
	require.Equal(t, http.StatusOK, valid.Code)
	require.Contains(t, unknownLogs, "bootstrap_token_unknown")
	require.NotContains(t, unknownLogs, "unknown-bootstrap-")
	require.NotContains(t, unknownLogs, "\"token_hash_prefix\"")
}

func TestOAuthTokenHandler_concurrent_unknown_bootstrap_tokens_share_rate_limit(t *testing.T) {
	// Given
	logs := useSynchronizedTestLogger(t)
	svc, _ := newRFC8693HandlerTestService(t)
	router := svc.newRouter(zerolog.New(logs))
	const unknownClientIP = "198.51.100.50:1234"
	start := make(chan struct{})
	statuses := make(chan int, 20)
	var workers sync.WaitGroup

	// When
	for attempt := range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			response := httptest.NewRecorder()
			request := bootstrapExchangeRequest(fmt.Sprintf("concurrent-unknown-%d", attempt))
			request.RemoteAddr = unknownClientIP
			router.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	close(start)
	workers.Wait()
	close(statuses)
	blocked := httptest.NewRecorder()
	blockedRequest := bootstrapExchangeRequest("concurrent-unknown-blocked")
	blockedRequest.RemoteAddr = unknownClientIP
	router.ServeHTTP(blocked, blockedRequest)

	// Then
	for status := range statuses {
		require.Contains(t, []int{http.StatusBadRequest, http.StatusTooManyRequests}, status)
	}
	require.Equal(t, http.StatusTooManyRequests, blocked.Code)
	require.Contains(t, logs.String(), "bootstrap_token_unknown")
	require.NotContains(t, logs.String(), "concurrent-unknown-")
	require.NotContains(t, logs.String(), "\"token_hash_prefix\"")
}
