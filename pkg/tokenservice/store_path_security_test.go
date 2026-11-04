package tokenservice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStoreConstructors_reject_symlinked_root(t *testing.T) {
	tests := []struct {
		name string
		open func(string) error
	}{
		{name: "bootstrap", open: func(path string) error { _, err := NewBootstrapTokenStore(path); return err }},
		{name: "refresh", open: func(path string) error { _, err := NewRefreshTokenStore(path); return err }},
		{name: "service identity policy", open: func(path string) error { _, err := NewServiceIdentityPolicyStore(path); return err }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			parent := t.TempDir()
			target := filepath.Join(parent, "target")
			require.NoError(t, os.Mkdir(target, 0o700))
			root := filepath.Join(parent, "store")
			require.NoError(t, os.Symlink(target, root))

			// When
			err := test.open(root)

			// Then
			require.Error(t, err)
		})
	}
}

func TestStoreConstructors_reject_non_directory_root(t *testing.T) {
	tests := []struct {
		name string
		open func(string) error
	}{
		{name: "bootstrap", open: func(path string) error { _, err := NewBootstrapTokenStore(path); return err }},
		{name: "refresh", open: func(path string) error { _, err := NewRefreshTokenStore(path); return err }},
		{name: "service identity policy", open: func(path string) error { _, err := NewServiceIdentityPolicyStore(path); return err }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			path := filepath.Join(t.TempDir(), "not-a-directory")
			require.NoError(t, os.WriteFile(path, nil, 0o600))

			// When
			err := test.open(path)

			// Then
			require.Error(t, err)
		})
	}
}

func TestBootstrapTokenStore_constructor_rejects_symlinked_JSON_record(t *testing.T) {
	// Given
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "policy.json")
	policy := &BootstrapTokenPolicy{ID: "policy", TokenHash: "hash", ExpiresAt: time.Now().Add(time.Hour)}
	data, err := json.Marshal(policy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(target, data, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "record.json")))

	// When
	_, err = NewBootstrapTokenStore(root)

	// Then
	require.Error(t, err)
}

func TestRefreshTokenStore_constructor_rejects_symlinked_JSON_record(t *testing.T) {
	// Given
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "family.json")
	family := &RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "hash", ExpiresAt: time.Now().Add(time.Hour)}
	data, err := json.Marshal(family)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(target, data, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "record.json")))

	// When
	_, err = NewRefreshTokenStore(root)

	// Then
	require.Error(t, err)
}

func TestServiceIdentityPolicyStore_List_rejects_symlinked_JSON_record(t *testing.T) {
	// Given
	root := t.TempDir()
	store, err := NewServiceIdentityPolicyStore(root)
	require.NoError(t, err)
	policy := testServiceIdentityPolicy(time.Now())
	target := filepath.Join(t.TempDir(), "policy.json")
	data, err := json.Marshal(policy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(target, data, 0o600))
	require.NoError(t, os.Symlink(target, filepath.Join(store.storePath, store.policyFileName(policy.Subject))))

	// When
	_, err = store.List()

	// Then
	require.ErrorIs(t, err, ErrServiceIdentityPolicyInvalid)
}

func TestPersistentStores_keep_operating_on_pinned_directory_after_path_replacement(t *testing.T) {
	// Given
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name string
		open func(t *testing.T, path string) func(t *testing.T)
	}{
		{
			name: "bootstrap",
			open: func(t *testing.T, path string) func(t *testing.T) {
				store, err := NewBootstrapTokenStore(path)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, store.Close()) })
				return func(t *testing.T) {
					require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "policy", TokenHash: "bootstrap", ExpiresAt: now.Add(time.Hour)}))
				}
			},
		},
		{
			name: "refresh",
			open: func(t *testing.T, path string) func(t *testing.T) {
				store, err := NewRefreshTokenStore(path)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, store.Close()) })
				return func(t *testing.T) {
					require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
				}
			},
		},
		{
			name: "service identity policy",
			open: func(t *testing.T, path string) func(t *testing.T) {
				store, err := NewServiceIdentityPolicyStore(path)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, store.Close()) })
				return func(t *testing.T) {
					require.NoError(t, store.Save(testServiceIdentityPolicy(now)))
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			configured := filepath.Join(parent, "configured")
			pinned := filepath.Join(parent, "pinned")
			attacker := filepath.Join(parent, "attacker")
			require.NoError(t, os.Mkdir(configured, 0o700))
			require.NoError(t, os.Mkdir(attacker, 0o700))
			operate := test.open(t, configured)
			require.NoError(t, os.Rename(configured, pinned))
			require.NoError(t, os.Symlink(attacker, configured))

			// When
			operate(t)

			// Then
			pinnedEntries, err := os.ReadDir(pinned)
			require.NoError(t, err)
			require.NotEmpty(t, pinnedEntries)
			attackerEntries, err := os.ReadDir(attacker)
			require.NoError(t, err)
			require.Empty(t, attackerEntries)
		})
	}
}

func TestPersistentStores_cleanup_stays_on_pinned_directory_after_path_replacement(t *testing.T) {
	// Given
	tests := []struct {
		name string
		open func(t *testing.T, path string) func(t *testing.T)
	}{
		{
			name: "bootstrap",
			open: func(t *testing.T, path string) func(t *testing.T) {
				store, err := NewBootstrapTokenStore(path)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, store.Close()) })
				require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "expired", TokenHash: "expired", ExpiresAt: time.Now().Add(-time.Hour)}))
				return func(t *testing.T) { require.NoError(t, store.CleanupExpired()) }
			},
		},
		{
			name: "refresh",
			open: func(t *testing.T, path string) func(t *testing.T) {
				store, err := NewRefreshTokenStore(path)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, store.Close()) })
				require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "expired", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(-time.Hour)}))
				return func(t *testing.T) { require.NoError(t, store.CleanupExpired()) }
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			configured := filepath.Join(parent, "configured")
			pinned := filepath.Join(parent, "pinned")
			attacker := filepath.Join(parent, "attacker")
			require.NoError(t, os.Mkdir(configured, 0o700))
			require.NoError(t, os.Mkdir(attacker, 0o700))
			cleanup := test.open(t, configured)
			require.NoError(t, os.Rename(configured, pinned))
			require.NoError(t, os.Symlink(attacker, configured))

			// When
			cleanup(t)

			// Then
			pinnedEntries, err := os.ReadDir(pinned)
			require.NoError(t, err)
			for _, entry := range pinnedEntries {
				require.NotEqual(t, "expired.json", entry.Name())
			}
			attackerEntries, err := os.ReadDir(attacker)
			require.NoError(t, err)
			require.Empty(t, attackerEntries)
		})
	}
}
