// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServiceIdentityPolicyStore_Create_allows_exactly_one_store_instance(t *testing.T) {
	// Given
	now := time.Now().UTC()
	path := t.TempDir()
	first, err := NewServiceIdentityPolicyStore(path)
	require.NoError(t, err)
	second, err := NewServiceIdentityPolicyStore(path)
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, store := range []*ServiceIdentityPolicyStore{first, second} {
		group.Add(1)
		go func(store *ServiceIdentityPolicyStore) {
			defer group.Done()
			<-start
			results <- store.Create(testServiceIdentityPolicy(now))
		}(store)
	}

	// When
	close(start)
	group.Wait()
	close(results)

	// Then
	winners := 0
	for err := range results {
		if err == nil {
			winners++
			continue
		}
		require.ErrorIs(t, err, ErrServiceIdentityPolicyExists)
	}
	require.Equal(t, 1, winners)
	policy, err := first.GetActive("boot-service", now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, "metadata-service", policy.Audience)
}

func TestServiceIdentityPolicyStore_Create_across_processes(t *testing.T) {
	if os.Getenv("TOKENSMITH_CREATE_POLICY_HELPER") == "1" {
		store, err := NewServiceIdentityPolicyStore(os.Getenv("TOKENSMITH_CREATE_POLICY_PATH"))
		require.NoError(t, err)
		require.NoError(t, store.Create(testServiceIdentityPolicy(time.Now().UTC())))
		return
	}

	// Given
	path := t.TempDir()
	newProcess := func() *exec.Cmd {
		command := exec.Command(os.Args[0], "-test.run=^TestServiceIdentityPolicyStore_Create_across_processes$")
		command.Env = append(os.Environ(), "TOKENSMITH_CREATE_POLICY_HELPER=1", "TOKENSMITH_CREATE_POLICY_PATH="+path)
		return command
	}
	first, second := newProcess(), newProcess()

	// When
	require.NoError(t, first.Start())
	require.NoError(t, second.Start())
	firstErr, secondErr := first.Wait(), second.Wait()

	// Then
	winners := 0
	if firstErr == nil {
		winners++
	}
	if secondErr == nil {
		winners++
	}
	require.Equal(t, 1, winners)
	store, err := NewServiceIdentityPolicyStore(path)
	require.NoError(t, err)
	_, err = store.GetActive("boot-service", time.Now().UTC())
	require.NoError(t, err)
}
