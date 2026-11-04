package tokenservice

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStoreRoot_Close_is_nil_safe_idempotent_and_concurrent(t *testing.T) {
	// Given
	root, err := openStoreRoot(t.TempDir())
	require.NoError(t, err)
	var nilRoot *storeRoot
	require.NoError(t, nilRoot.Close())

	// When
	errors := closeConcurrently(root.Close)

	// Then
	for _, err := range errors {
		require.NoError(t, err)
	}
	require.NoError(t, root.Close())
}

func TestCredentialStores_Close_are_nil_safe_idempotent_and_concurrent(t *testing.T) {
	// Given
	bootstrap, err := NewBootstrapTokenStore(t.TempDir())
	require.NoError(t, err)
	refresh, err := NewRefreshTokenStore(t.TempDir())
	require.NoError(t, err)
	var nilBootstrap *BootstrapTokenStore
	var nilRefresh *RefreshTokenStore
	require.NoError(t, nilBootstrap.Close())
	require.NoError(t, nilRefresh.Close())

	// When
	for _, closer := range []func() error{bootstrap.Close, refresh.Close} {
		errors := closeConcurrently(closer)
		for _, err := range errors {
			require.NoError(t, err)
		}
		require.NoError(t, closer())
	}
}

func closeConcurrently(closer func() error) []error {
	const callers = 8
	results := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- closer()
		}()
	}
	group.Wait()
	close(results)
	return collectCloseErrors(results)
}

func collectCloseErrors(results <-chan error) []error {
	errors := make([]error, 0, cap(results))
	for err := range results {
		errors = append(errors, err)
	}
	return errors
}
