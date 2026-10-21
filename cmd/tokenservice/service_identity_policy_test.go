// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceIdentityPolicyCommand_CreateListRevoke(t *testing.T) {
	storePath := t.TempDir()
	command := newServiceIdentityPolicyCmd()
	output := new(bytes.Buffer)
	command.SetOut(output)
	command.SetErr(output)
	command.SetArgs([]string{
		"create",
		"--service-identity-policy-store", storePath,
		"--subject", "boot-service",
		"--audience", "metadata-service",
		"--scopes", "read write",
		"--ttl", "1h",
		"--refresh-ttl", "30m",
	})
	require.NoError(t, command.Execute())
	assert.Contains(t, output.String(), "boot-service")
	assert.NotContains(t, output.String(), "token")

	command = newServiceIdentityPolicyCmd()
	output.Reset()
	command.SetOut(output)
	command.SetArgs([]string{"list", "--service-identity-policy-store", storePath})
	require.NoError(t, command.Execute())
	assert.Contains(t, output.String(), "metadata-service")
	assert.NotContains(t, output.String(), "refresh_token")

	command = newServiceIdentityPolicyCmd()
	command.SetArgs([]string{"revoke", "--service-identity-policy-store", storePath, "--subject", "boot-service"})
	require.NoError(t, command.Execute())

	command = newServiceIdentityPolicyCmd()
	output.Reset()
	command.SetOut(output)
	command.SetArgs([]string{"list", "--service-identity-policy-store", storePath})
	require.NoError(t, command.Execute())
	assert.Contains(t, output.String(), "revoked_at")
}

func TestServiceIdentityPolicyCommand_RejectsRefreshTTLOverPolicyTTL(t *testing.T) {
	command := newServiceIdentityPolicyCmd()
	command.SetArgs([]string{
		"create",
		"--service-identity-policy-store", t.TempDir(),
		"--subject", "boot-service",
		"--audience", "metadata-service",
		"--scopes", "read",
		"--ttl", "1h",
		"--refresh-ttl", "2h",
	})

	err := command.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not exceed")
}

func TestServiceIdentityPolicyCommand_UsesEnvironmentStoreForLifecycle(t *testing.T) {
	environmentStore := t.TempDir()
	t.Setenv("TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE", environmentStore)
	t.Chdir(t.TempDir())

	command := newServiceIdentityPolicyCmd()
	command.SetArgs([]string{"create", "--subject", "environment-service", "--audience", "metadata-service", "--scopes", "read", "--ttl", "1h", "--refresh-ttl", "30m"})
	require.NoError(t, command.Execute())

	store, err := tokenservice.NewServiceIdentityPolicyStore(environmentStore)
	require.NoError(t, err)
	policies, err := store.List()
	require.NoError(t, err)
	require.Len(t, policies, 1)

	output := new(bytes.Buffer)
	command = newServiceIdentityPolicyCmd()
	command.SetOut(output)
	command.SetArgs([]string{"list"})
	require.NoError(t, command.Execute())
	assert.Contains(t, output.String(), "environment-service")

	command = newServiceIdentityPolicyCmd()
	command.SetArgs([]string{"revoke", "--subject", "environment-service"})
	require.NoError(t, command.Execute())

	policies, err = store.List()
	require.NoError(t, err)
	require.NotNil(t, policies[0].RevokedAt)
}

func TestServiceIdentityPolicyCommand_UsesDefaultStoreWithoutEnvironment(t *testing.T) {
	t.Setenv("TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE", "")
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)

	command := newServiceIdentityPolicyCmd()
	command.SetArgs([]string{"create", "--subject", "default-service", "--audience", "metadata-service", "--scopes", "read", "--ttl", "1h", "--refresh-ttl", "30m"})
	require.NoError(t, command.Execute())

	store, err := tokenservice.NewServiceIdentityPolicyStore(filepath.Join(workingDirectory, "data", "service-identities"))
	require.NoError(t, err)
	policies, err := store.List()
	require.NoError(t, err)
	require.Len(t, policies, 1)
}

func TestServiceIdentityPolicyCommand_FlagOverridesEnvironmentStore(t *testing.T) {
	environmentStore := t.TempDir()
	flagStore := t.TempDir()
	t.Setenv("TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE", environmentStore)

	command := newServiceIdentityPolicyCmd()
	command.SetArgs([]string{"create", "--service-identity-policy-store", flagStore, "--subject", "flag-service", "--audience", "metadata-service", "--scopes", "read", "--ttl", "1h", "--refresh-ttl", "30m"})
	require.NoError(t, command.Execute())

	configuredStore, err := tokenservice.NewServiceIdentityPolicyStore(flagStore)
	require.NoError(t, err)
	policies, err := configuredStore.List()
	require.NoError(t, err)
	require.Len(t, policies, 1)

	environmentPolicyStore, err := tokenservice.NewServiceIdentityPolicyStore(environmentStore)
	require.NoError(t, err)
	environmentPolicies, err := environmentPolicyStore.List()
	require.NoError(t, err)
	assert.Empty(t, environmentPolicies)
}

func TestResolveServiceIdentityPolicyStorePath(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv("TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE", "")
		path, err := resolveServiceIdentityPolicyStorePath(newListServiceIdentityPolicyCmd())
		require.NoError(t, err)
		assert.Equal(t, defaultServiceIdentityPolicyStorePath, path)
	})
	t.Run("environment", func(t *testing.T) {
		t.Setenv("TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE", "/environment/store")
		path, err := resolveServiceIdentityPolicyStorePath(newListServiceIdentityPolicyCmd())
		require.NoError(t, err)
		assert.Equal(t, "/environment/store", path)
	})
	t.Run("flag", func(t *testing.T) {
		t.Setenv("TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE", "/environment/store")
		command := newListServiceIdentityPolicyCmd()
		require.NoError(t, command.Flags().Set("service-identity-policy-store", "/flag/store"))
		path, err := resolveServiceIdentityPolicyStorePath(command)
		require.NoError(t, err)
		assert.Equal(t, "/flag/store", path)
	})
}

func TestServeCommandHasServiceIdentityPolicyStoreFlag(t *testing.T) {
	flag := serveCmd.Flags().Lookup("service-identity-policy-store")
	require.NotNil(t, flag)
	assert.True(t, strings.Contains(flag.Usage, "TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE"))
	policyFlag := newListServiceIdentityPolicyCmd().Flags().Lookup("service-identity-policy-store")
	require.NotNil(t, policyFlag)
	assert.True(t, strings.Contains(policyFlag.Usage, "TOKENSMITH_SERVICE_IDENTITY_POLICY_STORE"))
}
