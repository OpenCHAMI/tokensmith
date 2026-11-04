// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
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

func TestNewTokenService_closes_policy_store_when_bootstrap_temp_creation_fails(t *testing.T) {
	// Given
	policyPath := t.TempDir()
	tempErr := errors.New("bootstrap temp failed")
	originalPolicyStore := newServiceIdentityPolicyStore
	originalMkdirTemp := makeStoreTemp
	var policyStore *ServiceIdentityPolicyStore
	newServiceIdentityPolicyStore = func(path string) (*ServiceIdentityPolicyStore, error) {
		store, err := originalPolicyStore(path)
		policyStore = store
		return store, err
	}
	makeStoreTemp = func(string, string) (string, error) { return "", tempErr }
	t.Cleanup(func() {
		newServiceIdentityPolicyStore = originalPolicyStore
		makeStoreTemp = originalMkdirTemp
	})

	// When
	_, err := NewTokenService(keys.NewKeyManager(), Config{ServiceIdentityPolicyStorePath: policyPath})

	// Then
	require.ErrorIs(t, err, tempErr)
	require.NotNil(t, policyStore)
	_, rootErr := policyStore.root.ReadDir()
	require.Error(t, rootErr)
}

func TestNewTokenService_joins_close_errors_when_refresh_initialization_fails(t *testing.T) {
	// Given
	policyPath := t.TempDir()
	bootstrapPath := t.TempDir()
	refreshErr := errors.New("refresh initialization failed")
	closeErr := errors.New("close failed")
	originalPolicyStore := newServiceIdentityPolicyStore
	originalBootstrapStore := newBootstrapTokenStore
	originalRefreshStore := newRefreshTokenStore
	originalCloseRoot := closeStoreRoot
	var policyStore *ServiceIdentityPolicyStore
	var bootstrapStore *BootstrapTokenStore
	newServiceIdentityPolicyStore = func(path string) (*ServiceIdentityPolicyStore, error) {
		store, err := originalPolicyStore(path)
		policyStore = store
		return store, err
	}
	newBootstrapTokenStore = func(path string) (*BootstrapTokenStore, error) {
		store, err := originalBootstrapStore(path)
		bootstrapStore = store
		return store, err
	}
	newRefreshTokenStore = func(string) (*RefreshTokenStore, error) { return nil, refreshErr }
	closeStoreRoot = func(root *os.Root) error { return errors.Join(root.Close(), closeErr) }
	t.Cleanup(func() {
		newServiceIdentityPolicyStore = originalPolicyStore
		newBootstrapTokenStore = originalBootstrapStore
		newRefreshTokenStore = originalRefreshStore
		closeStoreRoot = originalCloseRoot
	})

	// When
	_, err := NewTokenService(keys.NewKeyManager(), Config{
		ServiceIdentityPolicyStorePath: policyPath,
		RFC8693BootstrapStorePath:      bootstrapPath,
		RFC8693RefreshStorePath:        t.TempDir(),
	})

	// Then
	require.ErrorIs(t, err, refreshErr)
	require.ErrorIs(t, err, closeErr)
	require.NotNil(t, policyStore)
	require.NotNil(t, bootstrapStore)
	_, policyRootErr := policyStore.root.ReadDir()
	require.Error(t, policyRootErr)
	_, bootstrapRootErr := bootstrapStore.root.ReadDir()
	require.Error(t, bootstrapRootErr)
}
