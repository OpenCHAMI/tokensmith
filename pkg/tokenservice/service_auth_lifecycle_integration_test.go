// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAuthLifecycle_ReplacesTerminalBootstrapFamilyWithOneMTLSSession(t *testing.T) {
	// Given: separate bootstrap and active service-identity policies with missing client files.
	fixture := newServiceAuthLifecycleFixture(t, true)
	client := NewServiceClientWithOptions(fixture.server.URL, "metadata-service", "metadata-id", "instance-1", "cluster-integration", WithHTTPClient(fixture.server.Client()), WithBootstrapToken(lifecycleBootstrapSecret), WithTargetService("smd"), WithLifecycleTimeout(time.Second))
	require.NoError(t, client.Initialize(context.Background()), fixture.logs.String())
	require.Equal(t, int32(1), fixture.bootstrapCalls.Load())
	require.Equal(t, int32(0), fixture.sessionCalls.Load())
	require.NotNil(t, client.GetServiceToken())
	fixture.writeIdentityFiles(t)
	t.Setenv(ServiceIdentityCertEnvVar, fixture.certPath)
	t.Setenv(ServiceIdentityKeyEnvVar, fixture.keyPath)
	oldFamily := fixture.onlyRefreshFamily(t)
	waitForPublicRefreshExpiry(t, client)
	fixture.blockSession.Store(true)

	// When: a canceled creator and healthy public callers acquire a terminal replacement.
	creatorContext, cancelCreator := context.WithCancel(context.Background())
	creatorResult := make(chan error, 1)
	go func() { creatorResult <- client.ForceRefresh(creatorContext) }()
	<-fixture.sessionStarted
	cancelCreator()
	require.ErrorIs(t, <-creatorResult, context.Canceled)
	results := make(chan error, 2)
	var callers sync.WaitGroup
	for range 2 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			results <- client.ForceRefresh(context.Background())
		}()
	}
	close(fixture.sessionRelease)
	callers.Wait()
	close(results)

	// Then: the mTLS session is coalesced, the old family stays terminal, and secrets never persist.
	for result := range results {
		require.NoError(t, result)
	}
	assert.Equal(t, int32(1), fixture.bootstrapCalls.Load())
	assert.Equal(t, int32(1), fixture.sessionCalls.Load())
	persistedOld, err := fixture.service.refreshTokenStore.GetFamily(oldFamily.FamilyID)
	require.NoError(t, err)
	assert.False(t, time.Now().Before(persistedOld.ExpiresAt))
	entries := fixture.refreshFamilyEntries(t)
	assert.Len(t, entries, 2)
	lockData, err := os.ReadFile(filepath.Join(fixture.root, "refresh", ".store.lock"))
	require.NoError(t, err)
	assert.NotContains(t, string(lockData), lifecycleBootstrapSecret)
	assert.NotContains(t, string(lockData), "eyJ")
	persisted := fixture.persistedText(t)
	assert.NotContains(t, persisted, lifecycleBootstrapSecret)
	assert.NotContains(t, persisted, "eyJ")
	bootstrapPolicy, err := fixture.service.bootstrapTokenStore.GetPolicy(HashBootstrapToken(lifecycleBootstrapSecret))
	require.NoError(t, err)
	assert.NotNil(t, bootstrapPolicy.ConsumedAt)
}

func TestServiceAuthLifecycle_AutoRefreshStopsAfterTerminalFailureAndExplicitGetTokenRetries(t *testing.T) {
	// Given: a public one-second refresh session whose policy is later revoked through its store.
	fixture := newServiceAuthLifecycleFixture(t, false)
	shortPolicy := serviceAuthIdentityPolicy(time.Now().UTC())
	shortPolicy.ExpiresAt = shortPolicy.CreatedAt.Add(2 * time.Second)
	shortPolicy.RefreshTTL = time.Second
	require.NoError(t, fixture.service.serviceIdentityPolicyStore.Save(shortPolicy))
	fixture.writeIdentityFiles(t)
	client := fixture.client(WithAutoRefreshInterval(time.Millisecond))
	require.NoError(t, client.Initialize(context.Background()), fixture.logs.String())
	<-fixture.sessionRequests
	require.NoError(t, fixture.service.serviceIdentityPolicyStore.Revoke("metadata-service", time.Now().UTC()))
	waitForPublicRefreshExpiry(t, client)
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.StartAutoRefresh(context.Background())
	}()

	// When: automatic refresh reaches a real router policy denial.
	<-fixture.sessionRequests
	<-done

	// Then: it records one failure, exits, and a newly provisioned policy allows explicit recovery.
	assert.Equal(t, uint64(1), client.Stats().RefreshFailures)
	assert.Equal(t, int32(2), fixture.sessionCalls.Load())
	require.NoError(t, fixture.service.serviceIdentityPolicyStore.Save(serviceAuthIdentityPolicy(time.Now().UTC())))
	require.NoError(t, client.ForceRefresh(context.Background()))
	assert.Equal(t, int32(3), fixture.sessionCalls.Load())
	assert.Equal(t, uint64(2), client.Stats().RefreshSuccesses)
}

func waitForPublicRefreshExpiry(t *testing.T, client *ServiceClient) {
	t.Helper()
	deadline := client.Stats().RefreshExpiresAt
	require.False(t, deadline.IsZero())
	deadlineTimer := time.NewTimer(time.Until(deadline))
	hardTimeout := time.NewTimer(5 * time.Second)
	defer deadlineTimer.Stop()
	defer hardTimeout.Stop()
	select {
	case <-deadlineTimer.C:
	case <-hardTimeout.C:
		t.Fatal("public refresh expiry deadline was not reached")
	}
}
