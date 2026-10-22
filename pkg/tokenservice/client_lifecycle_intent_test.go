// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceClientRefreshTokenIfNeeded_ConditionalOwnerRechecksFreshness(t *testing.T) {
	// Given: a refresh operation held open while conditional callers accumulate.
	var refreshRequests atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		if r.FormValue("grant_type") != GrantTypeRefreshTokenRFC8693 {
			_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "initial", ExpiresIn: 60, RefreshToken: "refresh", RefreshExpiresIn: 3600})
			return
		}
		refreshRequests.Add(1)
		close(started)
		<-release
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "rotated", ExpiresIn: 7200, RefreshToken: "refresh-2", RefreshExpiresIn: 3600})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"), WithRefreshBefore(time.Hour))
	require.NoError(t, client.Initialize(context.Background()))

	var callers sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		callers.Add(1)
		go func() { defer callers.Done(); errs <- client.RefreshTokenIfNeeded(context.Background()) }()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("refresh request did not start")
	}
	close(release)
	callers.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// When: a late conditional caller crosses the completed owner boundary.
	require.NoError(t, client.RefreshTokenIfNeeded(context.Background()))

	// Then: exactly one refresh request occurred after initialization.
	assert.Equal(t, int32(1), refreshRequests.Load())
}

func TestServiceClientGetToken_ForcedCallsRotateAfterSharedOperation(t *testing.T) {
	// Given: forced token acquisition with the second request held open.
	var requests atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requests.Add(1)
		if count == 2 {
			close(started)
			<-release
		}
		_ = json.NewEncoder(w).Encode(OAuthTokenResponse{AccessToken: "access", ExpiresIn: 7200, RefreshToken: "refresh", RefreshExpiresIn: 3600})
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"))
	require.NoError(t, client.Initialize(context.Background()))

	var callers sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		callers.Add(1)
		go func() { defer callers.Done(); errs <- client.ForceRefresh(context.Background()) }()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("forced request did not start")
	}
	close(release)
	callers.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	// Then: concurrent forced callers share one operation, and a later call rotates again.
	require.NoError(t, client.ForceRefresh(context.Background()))
	assert.Equal(t, int32(3), requests.Load())
}

func TestServiceClientForceRefresh_PublishesFailureStatsBeforeWaitersReturn(t *testing.T) {
	// Given: a shared terminal request held until all public callers are waiting.
	started, release := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(started)
			<-release
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	client := NewServiceClientWithOptions(server.URL, "service", "id", "instance", "cluster", WithBootstrapToken("bootstrap"), WithTargetService("target"))
	errs := make(chan error, 2)
	go func() { errs <- client.ForceRefresh(context.Background()) }()
	<-started
	observedDone := make(chan struct{})
	go func() {
		errs <- client.ForceRefresh(&observingContext{Context: context.Background(), observedDone: observedDone})
	}()
	<-observedDone
	close(release)
	firstErr := <-errs
	require.Error(t, firstErr)
	stats := client.Stats()
	assert.Equal(t, uint64(1), stats.RefreshFailures)
	assert.False(t, stats.LastRefresh.IsZero())
	assert.NotEmpty(t, stats.LastError)
	for range 1 {
		waiterErr := <-errs
		require.EqualError(t, waiterErr, firstErr.Error())
		stats := client.Stats()
		assert.Equal(t, uint64(1), stats.RefreshFailures)
		assert.False(t, stats.LastRefresh.IsZero())
		assert.NotEmpty(t, stats.LastError)
	}
	assert.Equal(t, int32(1), requests.Load())
}

type observingContext struct {
	context.Context
	observedDone chan struct{}
	once         sync.Once
}

func (c *observingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observedDone) })
	return c.Context.Done()
}
