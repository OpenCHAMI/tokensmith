package tokenservice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBootstrapTokenStore_CleanupExpired_rejects_nested_token_hash(t *testing.T) {
	// Given
	path := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(path, "nested"), 0o700))
	sentinel := filepath.Join(path, "nested", "victim.json")
	require.NoError(t, os.WriteFile(sentinel, []byte("sentinel"), 0o600))
	policy := &BootstrapTokenPolicy{ID: "expired", TokenHash: "nested/victim", ExpiresAt: time.Now().Add(-time.Hour)}
	data, err := json.Marshal(policyToDisk(policy))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, "record.json"), data, 0o600))
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	// When
	err = store.CleanupExpired()

	// Then
	require.ErrorContains(t, err, "safe basename")
	_, err = os.Stat(sentinel)
	require.NoError(t, err)
}

func TestRefreshTokenStore_CleanupExpired_rejects_nested_family_ID(t *testing.T) {
	// Given
	path := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(path, "nested"), 0o700))
	sentinel := filepath.Join(path, "nested", "victim.json")
	require.NoError(t, os.WriteFile(sentinel, []byte("sentinel"), 0o600))
	family := &RefreshTokenFamily{FamilyID: "nested/victim", CurrentTokenHash: "current", ExpiresAt: time.Now().Add(-time.Hour)}
	data, err := json.Marshal(familyToDisk(family))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, "record.json"), data, 0o600))
	store, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	// When
	err = store.CleanupExpired()

	// Then
	require.ErrorContains(t, err, "safe basename")
	_, err = os.Stat(sentinel)
	require.NoError(t, err)
}

func TestCredentialStores_cleanup_stays_on_pinned_directory_after_path_replacement(t *testing.T) {
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
			// Given
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
