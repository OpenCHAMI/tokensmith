// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenService_RejectsServiceIdentityPolicyStoreFile(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(storePath, []byte("not a store"), 0o600))
	_, err := NewTokenService(keys.NewKeyManager(), Config{ServiceIdentityPolicyStorePath: storePath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service identity policy store")
}

func TestNewTokenService_UsesExternallyUpdatedServiceIdentityPolicyStore(t *testing.T) {
	storePath := t.TempDir()
	store, err := NewServiceIdentityPolicyStore(storePath)
	require.NoError(t, err)
	now := time.Now().UTC()
	policy := serviceIdentityPolicyForHandler(now, "server-service")
	require.NoError(t, store.Save(policy))
	service, err := NewTokenService(keys.NewKeyManager(), Config{ServiceIdentityPolicyStorePath: storePath})
	require.NoError(t, err)
	_, err = service.serviceIdentityPolicyStore.GetActive(policy.Subject, now.Add(time.Second))
	require.NoError(t, err)
	require.NoError(t, store.Revoke(policy.Subject, now.Add(time.Minute)))
	_, err = service.serviceIdentityPolicyStore.GetActive(policy.Subject, now.Add(2*time.Minute))
	assert.ErrorIs(t, err, ErrServiceIdentityPolicyRevoked)
}
