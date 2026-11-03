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

func TestServiceIdentityPolicyStore_mutations_wait_for_shared_store_lock(t *testing.T) {
	for _, test := range []struct {
		name      string
		prepare   func(*ServiceIdentityPolicyStore, time.Time) error
		operation func(*ServiceIdentityPolicyStore, time.Time) error
	}{
		{
			name: "create",
			prepare: func(_ *ServiceIdentityPolicyStore, _ time.Time) error {
				return nil
			},
			operation: func(store *ServiceIdentityPolicyStore, now time.Time) error {
				return store.Create(testServiceIdentityPolicy(now))
			},
		},
		{
			name: "save",
			prepare: func(store *ServiceIdentityPolicyStore, now time.Time) error {
				return store.Save(testServiceIdentityPolicy(now))
			},
			operation: func(store *ServiceIdentityPolicyStore, now time.Time) error {
				return store.Save(testServiceIdentityPolicy(now))
			},
		},
		{
			name: "revoke",
			prepare: func(store *ServiceIdentityPolicyStore, now time.Time) error {
				return store.Save(testServiceIdentityPolicy(now))
			},
			operation: func(store *ServiceIdentityPolicyStore, now time.Time) error {
				return store.Revoke("boot-service", now)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Given
			path := t.TempDir()
			store, err := NewServiceIdentityPolicyStore(path)
			require.NoError(t, err)
			now := time.Now().UTC()
			require.NoError(t, test.prepare(store, now))
			release := holdStoreLock(t, path)
			var releaseOnce sync.Once
			unlock := func() { releaseOnce.Do(release) }
			t.Cleanup(unlock)
			attempted := make(chan struct{}, 1)
			originalBeforeFlock := beforeStoreFlock
			beforeStoreFlock = func() { attempted <- struct{}{} }
			t.Cleanup(func() { beforeStoreFlock = originalBeforeFlock })
			result := make(chan error, 1)

			// When
			go func() { result <- test.operation(store, now.Add(time.Second)) }()
			select {
			case <-attempted:
			case <-time.After(time.Second):
				t.Fatal("policy mutation did not attempt the shared filesystem lock")
			}
			select {
			case err := <-result:
				t.Fatalf("policy mutation completed while lock was held: %v", err)
			default:
			}
			unlock()
			err = <-result

			// Then
			require.NoError(t, err)
		})
	}
}

func TestServiceIdentityPolicyStore_Save_across_processes_assigns_monotonic_revisions(t *testing.T) {
	// Given
	path := t.TempDir()
	store, err := NewServiceIdentityPolicyStore(path)
	require.NoError(t, err)
	require.NoError(t, store.Save(testServiceIdentityPolicy(time.Now().UTC())))

	// When
	first := serviceIdentityPolicyProcess(path, "save")
	second := serviceIdentityPolicyProcess(path, "save")
	require.NoError(t, first.Start())
	require.NoError(t, second.Start())
	require.NoError(t, first.Wait())
	require.NoError(t, second.Wait())
	policy, err := store.GetActive("boot-service", time.Now().UTC())

	// Then
	require.NoError(t, err)
	require.Equal(t, uint64(3), policy.Revision)
}

func TestServiceIdentityPolicyStore_ProcessHelper(t *testing.T) {
	mode := os.Getenv("TOKENSMITH_POLICY_HELPER")
	if mode == "" {
		return
	}
	store, err := NewServiceIdentityPolicyStore(os.Getenv("TOKENSMITH_POLICY_PATH"))
	require.NoError(t, err)
	switch mode {
	case "save":
		require.NoError(t, store.Save(testServiceIdentityPolicy(time.Now().UTC())))
	case "revoke":
		require.NoError(t, store.Revoke("boot-service", time.Now().UTC()))
	default:
		t.Fatalf("unsupported policy helper mode %q", mode)
	}
}

func serviceIdentityPolicyProcess(path, mode string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestServiceIdentityPolicyStore_ProcessHelper$")
	command.Env = append(os.Environ(), "TOKENSMITH_POLICY_HELPER="+mode, "TOKENSMITH_POLICY_PATH="+path)
	return command
}
