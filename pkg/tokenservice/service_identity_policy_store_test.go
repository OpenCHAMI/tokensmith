// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceIdentityPolicyStore_GetActive(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, err := NewServiceIdentityPolicyStore(t.TempDir())
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(now)
	require.NoError(t, store.Save(policy))
	got, err := store.GetActive("  boot-service  ", now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, policy.Subject, got.Subject)
	assert.Equal(t, policy.ExpiresAt, got.ExpiresAt)
	got.Scopes[0] = "mutated"
	again, err := store.GetActive(policy.Subject, now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, "read", again.Scopes[0])
}

func TestServiceIdentityPolicyStore_GetActiveDeniesInvalidStates(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name    string
		setup   func(t *testing.T, store *ServiceIdentityPolicyStore)
		wantErr error
	}{
		{name: "missing", setup: func(_ *testing.T, _ *ServiceIdentityPolicyStore) {}, wantErr: ErrServiceIdentityPolicyNotFound},
		{name: "exact expiry boundary", setup: func(t *testing.T, store *ServiceIdentityPolicyStore) {
			policy := testServiceIdentityPolicy(now)
			policy.CreatedAt = now.Add(-time.Hour)
			policy.ExpiresAt = now
			require.NoError(t, store.Save(policy))
		}, wantErr: ErrServiceIdentityPolicyExpired},
		{name: "revoked", setup: func(t *testing.T, store *ServiceIdentityPolicyStore) {
			policy := testServiceIdentityPolicy(now)
			require.NoError(t, store.Save(policy))
			require.NoError(t, store.Revoke(policy.Subject, now))
		}, wantErr: ErrServiceIdentityPolicyRevoked},
		{name: "corrupt", setup: func(t *testing.T, store *ServiceIdentityPolicyStore) {
			require.NoError(t, os.WriteFile(store.policyPath("boot-service"), []byte("{"), 0o600))
		}, wantErr: ErrServiceIdentityPolicyInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := NewServiceIdentityPolicyStore(t.TempDir())
			require.NoError(t, err)
			test.setup(t, store)
			_, err = store.GetActive("boot-service", now)
			require.Error(t, err)
			assert.True(t, errors.Is(err, test.wantErr), err)
		})
	}
}

func TestServiceIdentityPolicyStore_PersistsRevocationAndReadsDiskUpdates(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	storePath := t.TempDir()
	store, err := NewServiceIdentityPolicyStore(storePath)
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(now)
	require.NoError(t, store.Save(policy))
	require.NoError(t, store.Revoke(policy.Subject, now.Add(time.Minute)))
	reloaded, err := NewServiceIdentityPolicyStore(storePath)
	require.NoError(t, err)
	_, err = reloaded.GetActive(policy.Subject, now.Add(2*time.Minute))
	assert.ErrorIs(t, err, ErrServiceIdentityPolicyRevoked)
	updated := testServiceIdentityPolicy(now)
	updated.Audience = "updated-audience"
	require.NoError(t, store.Save(updated))
	got, err := reloaded.GetActive(updated.Subject, now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, "updated-audience", got.Audience)
	entries, err := os.ReadDir(storePath)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, filepath.Base(store.policyPath(policy.Subject)), entries[0].Name())
	assert.NotContains(t, entries[0].Name(), policy.Subject)
}

func TestServiceIdentityPolicyStore_RejectsInvalidPolicy(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, err := NewServiceIdentityPolicyStore(t.TempDir())
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(now)
	policy.RefreshTTL = 2 * time.Hour
	err = store.Save(policy)
	assert.ErrorIs(t, err, ErrServiceIdentityPolicyInvalid)
}

func TestServiceIdentityPolicyStore_RejectsDuplicateSubjectFiles(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	storePath := t.TempDir()
	store, err := NewServiceIdentityPolicyStore(storePath)
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(now)
	require.NoError(t, store.Save(policy))
	duplicate, err := json.Marshal(policy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(storePath, "duplicate.json"), duplicate, 0o600))
	_, err = store.GetActive(policy.Subject, now.Add(time.Second))
	assert.ErrorIs(t, err, ErrServiceIdentityPolicyInvalid)
}

func TestServiceIdentityPolicyStore_RejectsCorruptSiblingPolicyFile(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	storePath := t.TempDir()
	store, err := NewServiceIdentityPolicyStore(storePath)
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(now)
	require.NoError(t, store.Save(policy))
	require.NoError(t, os.WriteFile(filepath.Join(storePath, "corrupt.json"), []byte("{"), 0o600))
	_, err = store.GetActive(policy.Subject, now.Add(time.Second))
	assert.ErrorIs(t, err, ErrServiceIdentityPolicyInvalid)
}

func TestServiceIdentityPolicyStore_SaveDoesNotMutateCallerPolicy(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store, err := NewServiceIdentityPolicyStore(t.TempDir())
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(now)
	policy.Subject = "  boot-service  "
	require.NoError(t, store.Save(policy))
	assert.Equal(t, "  boot-service  ", policy.Subject)
}
