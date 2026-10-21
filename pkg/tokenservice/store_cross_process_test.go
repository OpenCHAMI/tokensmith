package tokenservice

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStoreProcessHelper(t *testing.T) {
	mode := os.Getenv("TOKENSMITH_STORE_HELPER")
	if mode == "" {
		return
	}
	_, err := io.ReadAll(os.Stdin)
	require.NoError(t, err)
	path, output := os.Getenv("TOKENSMITH_STORE_PATH"), os.Getenv("TOKENSMITH_STORE_RESULT")
	now := time.Now().UTC()
	result := "error"
	switch mode {
	case "bootstrap":
		store, err := NewBootstrapTokenStore(path)
		require.NoError(t, err)
		_, err = store.ConsumePolicy("bootstrap", "127.0.0.1", now)
		if err == nil {
			result = "ok"
		} else if errors.Is(err, ErrBootstrapTokenConsumed) {
			result = "consumed"
		}
	case "refresh":
		store, err := NewRefreshTokenStore(path)
		require.NoError(t, err)
		_, err = store.RotateOrRevoke("current", os.Getenv("TOKENSMITH_SUCCESSOR"), now)
		if err == nil {
			result = "ok"
		} else if errors.Is(err, ErrRefreshTokenReplay) {
			result = "replay"
		} else if errors.Is(err, ErrRefreshTokenRevoked) {
			result = "revoked"
		}
	case "save":
		store, err := NewRefreshTokenStore(path)
		require.NoError(t, err)
		err = store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: os.Getenv("TOKENSMITH_SUCCESSOR"), ExpiresAt: now.Add(time.Hour)})
		if err == nil {
			result = "ok"
		} else if errors.Is(err, ErrRefreshTokenFamilyExists) {
			result = "exists"
		}
	case "lock":
		lock, err := lockStore(path)
		require.NoError(t, err)
		_ = lock
		require.NoError(t, os.WriteFile(output, []byte("locked"), 0o600))
		os.Exit(0)
	}
	require.NoError(t, os.WriteFile(output, []byte(result), 0o600))
}

func TestBootstrapTokenStore_ConsumePolicy_across_processes(t *testing.T) {
	path := t.TempDir()
	now := time.Now().UTC()
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "policy", TokenHash: "bootstrap", ExpiresAt: now.Add(time.Hour)}))
	results := runStoreHelpers(t, "bootstrap", path, "", "")
	require.ElementsMatch(t, []string{"ok", "consumed"}, results)
	reopened, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	_, err = reopened.ConsumePolicy("bootstrap", "127.0.0.1", now)
	require.ErrorIs(t, err, ErrBootstrapTokenConsumed)
}

func TestRefreshTokenStore_RotateOrRevoke_across_processes(t *testing.T) {
	path := t.TempDir()
	now := time.Now().UTC()
	store, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	require.NoError(t, store.SaveFamily(&RefreshTokenFamily{FamilyID: "family", CurrentTokenHash: "current", ExpiresAt: now.Add(time.Hour)}))
	results := runStoreHelpers(t, "refresh", path, "one", "two")
	require.Contains(t, results, "ok")
	require.True(t, results[0] == "replay" || results[1] == "replay" || results[0] == "revoked" || results[1] == "revoked")
	reopened, err := NewRefreshTokenStore(path)
	require.NoError(t, err)
	family, err := reopened.GetFamily("family")
	require.NoError(t, err)
	require.NotNil(t, family.RevokedAt)
	_, err = reopened.RotateOrRevoke(family.CurrentTokenHash, "next", now)
	require.ErrorIs(t, err, ErrRefreshTokenRevoked)
}

func TestRefreshTokenStore_SaveFamily_duplicate_ID_across_processes(t *testing.T) {
	results := runStoreHelpers(t, "save", t.TempDir(), "one", "two")
	require.ElementsMatch(t, []string{"ok", "exists"}, results)
}

func TestStoreLock_releases_after_process_exit(t *testing.T) {
	path := t.TempDir()
	result := filepath.Join(path, "lock-result")
	command := storeHelper(path, "lock", "", result)
	input, err := command.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	require.NoError(t, input.Close())
	require.NoError(t, command.Wait())
	store, err := NewBootstrapTokenStore(path)
	require.NoError(t, err)
	require.NoError(t, store.SavePolicy(&BootstrapTokenPolicy{ID: "policy", TokenHash: "bootstrap", ExpiresAt: time.Now().Add(time.Hour)}))
}

func runStoreHelpers(t *testing.T, mode, path, first, second string) []string {
	t.Helper()
	commands := []*exec.Cmd{storeHelper(path, mode, first, filepath.Join(path, "first")), storeHelper(path, mode, second, filepath.Join(path, "second"))}
	inputs := make([]io.WriteCloser, 0, len(commands))
	for _, command := range commands {
		input, err := command.StdinPipe()
		require.NoError(t, err)
		inputs = append(inputs, input)
		require.NoError(t, command.Start())
	}
	for _, input := range inputs {
		require.NoError(t, input.Close())
	}
	for _, command := range commands {
		require.NoError(t, command.Wait())
	}
	results := make([]string, 0, len(commands))
	for _, name := range []string{"first", "second"} {
		data, err := os.ReadFile(filepath.Join(path, name))
		require.NoError(t, err)
		results = append(results, string(data))
	}
	return results
}

func storeHelper(path, mode, successor, output string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestStoreProcessHelper$")
	command.Env = append(os.Environ(), "TOKENSMITH_STORE_HELPER="+mode, "TOKENSMITH_STORE_PATH="+path, "TOKENSMITH_SUCCESSOR="+successor, "TOKENSMITH_STORE_RESULT="+output)
	return command
}
