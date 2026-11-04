// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAuthLifecycle_RejectsMissingExpiredAndRevokedIdentityPolicies(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, fixture *serviceAuthLifecycleFixture)
	}{
		{
			name:  "bootstrap policy alone",
			setup: func(_ *testing.T, _ *serviceAuthLifecycleFixture) {},
		},
		{
			name: "expired identity policy",
			setup: func(t *testing.T, fixture *serviceAuthLifecycleFixture) {
				policy := serviceAuthIdentityPolicy(time.Now().Add(-2 * time.Hour))
				policy.ExpiresAt = time.Now().Add(-time.Hour)
				require.NoError(t, fixture.service.serviceIdentityPolicyStore.Create(policy))
			},
		},
		{
			name: "revoked identity policy",
			setup: func(t *testing.T, fixture *serviceAuthLifecycleFixture) {
				now := time.Now().UTC()
				require.NoError(t, fixture.service.serviceIdentityPolicyStore.Create(serviceAuthIdentityPolicy(now)))
				require.NoError(t, fixture.service.serviceIdentityPolicyStore.Revoke("metadata-service", now))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: a real router with bootstrap policy but no active mTLS authorization.
			fixture := newServiceAuthLifecycleFixture(t, false)
			test.setup(t, fixture)
			fixture.writeIdentityFiles(t)

			// When: the public client requests a service-identity session.
			err := fixture.client().ForceRefresh(context.Background())

			// Then: the dedicated policy is required and bootstrap cannot authorize mTLS.
			require.Error(t, err)
			assert.ErrorContains(t, err, "status=403")
			assert.ErrorContains(t, err, "oauth_error=invalid_client")
			assert.Equal(t, int32(1), fixture.sessionCalls.Load())
			assert.Equal(t, int32(0), fixture.bootstrapCalls.Load())
		})
	}
}

func TestServiceAuthLifecycle_RejectsInvalidIdentityMaterialBeforeRequest(t *testing.T) {
	// Given: malformed client identity files.
	fixture := newServiceAuthLifecycleFixture(t, true)
	require.NoError(t, os.WriteFile(fixture.certPath, []byte("not a certificate"), 0o600))
	require.NoError(t, os.WriteFile(fixture.keyPath, []byte("not a key"), 0o600))

	// When: the public client attempts the session exchange.
	client := fixture.client()
	err := client.ForceRefresh(context.Background())

	// Then: local validation prevents any credential-bearing request.
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTLSClientMaterial))
	assert.Equal(t, int32(0), fixture.sessionCalls.Load())
}

func TestServiceAuthLifecycle_RedactsOversizedCredentialBearingSessionFailure(t *testing.T) {
	// Given: a real router policy denial transformed only after its handler has executed.
	fixture := newServiceAuthLifecycleFixture(t, true)
	fixture.writeIdentityFiles(t)
	fixture.failureBody = lifecycleBootstrapSecret + strings.Repeat("x", maximumErrorBodyBytes)
	require.NoError(t, fixture.service.serviceIdentityPolicyStore.Revoke("metadata-service", time.Now().UTC()))
	fixture.transformFailure.Store(true)

	// When: terminal service identity acquisition fails.
	client := fixture.client()
	err := client.ForceRefresh(context.Background())

	// Then: the public and diagnostic errors preserve only bounded metadata.
	require.Error(t, err)
	assert.ErrorContains(t, err, "status=403")
	assert.ErrorContains(t, err, "body_truncated=true")
	assert.NotContains(t, err.Error(), lifecycleBootstrapSecret)
	assert.NotContains(t, client.Stats().LastError, lifecycleBootstrapSecret)
	assert.Less(t, len(err.Error()), 256)
	<-fixture.sessionRequests
	assert.Contains(t, fixture.logs.String(), "failure_class")
}
