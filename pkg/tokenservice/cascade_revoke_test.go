// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHierarchyStorageForCascade struct {
	hierarchies map[string][]*TokenHierarchy
}

func newMockHierarchyStorageForCascade() *mockHierarchyStorageForCascade {
	return &mockHierarchyStorageForCascade{
		hierarchies: make(map[string][]*TokenHierarchy),
	}
}

func (m *mockHierarchyStorageForCascade) GetHierarchyByChildID(ctx context.Context, childID string) (*TokenHierarchy, error) {
	return nil, ErrParentTokenNotFound
}

func (m *mockHierarchyStorageForCascade) ListHierarchiesByParentID(ctx context.Context, parentID string) ([]*TokenHierarchy, error) {
	if children, ok := m.hierarchies[parentID]; ok {
		return children, nil
	}
	return []*TokenHierarchy{}, nil
}

func (m *mockHierarchyStorageForCascade) addChild(parentID, childID string, depth int) {
	if _, ok := m.hierarchies[parentID]; !ok {
		m.hierarchies[parentID] = make([]*TokenHierarchy, 0)
	}
	m.hierarchies[parentID] = append(m.hierarchies[parentID], &TokenHierarchy{
		ParentTokenID: parentID,
		ChildTokenID:  childID,
		Subject:       "user-123",
		Depth:         depth,
	})
}

func TestRevokeWithCascade_SingleLevel(t *testing.T) {
	storage := newMockHierarchyStorageForCascade()
	revocationStore := NewRevocationStore()

	storage.addChild("root-jti", "child1-jti", 1)
	storage.addChild("root-jti", "child2-jti", 1)

	svc := &TokenService{
		hierarchyStorage: storage,
		revocationStore:  revocationStore,
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err := svc.RevokeWithCascade(context.Background(), "root-jti", expiresAt)
	require.NoError(t, err)

	assert.True(t, revocationStore.IsRevoked("root-jti"), "Parent should be revoked")
	assert.True(t, revocationStore.IsRevoked("child1-jti"), "Child1 should be revoked")
	assert.True(t, revocationStore.IsRevoked("child2-jti"), "Child2 should be revoked")
}

func TestRevokeWithCascade_MultiLevel(t *testing.T) {
	storage := newMockHierarchyStorageForCascade()
	revocationStore := NewRevocationStore()

	storage.addChild("root-jti", "child1-jti", 1)
	storage.addChild("child1-jti", "grandchild1-jti", 2)
	storage.addChild("child1-jti", "grandchild2-jti", 2)
	storage.addChild("root-jti", "child2-jti", 1)
	storage.addChild("child2-jti", "grandchild3-jti", 2)

	svc := &TokenService{
		hierarchyStorage: storage,
		revocationStore:  revocationStore,
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err := svc.RevokeWithCascade(context.Background(), "root-jti", expiresAt)
	require.NoError(t, err)

	assert.True(t, revocationStore.IsRevoked("root-jti"), "Root should be revoked")
	assert.True(t, revocationStore.IsRevoked("child1-jti"), "Child1 should be revoked")
	assert.True(t, revocationStore.IsRevoked("child2-jti"), "Child2 should be revoked")
	assert.True(t, revocationStore.IsRevoked("grandchild1-jti"), "Grandchild1 should be revoked")
	assert.True(t, revocationStore.IsRevoked("grandchild2-jti"), "Grandchild2 should be revoked")
	assert.True(t, revocationStore.IsRevoked("grandchild3-jti"), "Grandchild3 should be revoked")
}

func TestRevokeWithCascade_NoChildren(t *testing.T) {
	storage := newMockHierarchyStorageForCascade()
	revocationStore := NewRevocationStore()

	svc := &TokenService{
		hierarchyStorage: storage,
		revocationStore:  revocationStore,
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err := svc.RevokeWithCascade(context.Background(), "root-jti", expiresAt)
	require.NoError(t, err)

	assert.True(t, revocationStore.IsRevoked("root-jti"), "Root should be revoked")
}

func TestRevokeWithCascade_NilStorage(t *testing.T) {
	revocationStore := NewRevocationStore()

	svc := &TokenService{
		hierarchyStorage: nil,
		revocationStore:  revocationStore,
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err := svc.RevokeWithCascade(context.Background(), "root-jti", expiresAt)
	require.NoError(t, err)

	assert.True(t, revocationStore.IsRevoked("root-jti"), "Root should be revoked even without storage")
}

func TestRevokeWithCascade_DeepHierarchy(t *testing.T) {
	storage := newMockHierarchyStorageForCascade()
	revocationStore := NewRevocationStore()

	current := "root-jti"
	for i := 1; i <= 10; i++ {
		childID := fmt.Sprintf("level-%d-jti", i)
		storage.addChild(current, childID, i)
		current = childID
	}

	svc := &TokenService{
		hierarchyStorage: storage,
		revocationStore:  revocationStore,
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err := svc.RevokeWithCascade(context.Background(), "root-jti", expiresAt)
	require.NoError(t, err)

	assert.True(t, revocationStore.IsRevoked("root-jti"), "Root should be revoked")
	for i := 1; i <= 10; i++ {
		jti := fmt.Sprintf("level-%d-jti", i)
		assert.True(t, revocationStore.IsRevoked(jti), "Level %d should be revoked", i)
	}
}

func TestRevokeWithCascade_PartialRevocation(t *testing.T) {
	storage := newMockHierarchyStorageForCascade()
	revocationStore := NewRevocationStore()

	storage.addChild("root-jti", "child1-jti", 1)
	storage.addChild("root-jti", "child2-jti", 1)
	storage.addChild("child2-jti", "grandchild1-jti", 2)

	svc := &TokenService{
		hierarchyStorage: storage,
		revocationStore:  revocationStore,
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	err := svc.RevokeWithCascade(context.Background(), "child2-jti", expiresAt)
	require.NoError(t, err)

	assert.False(t, revocationStore.IsRevoked("root-jti"), "Root should NOT be revoked")
	assert.False(t, revocationStore.IsRevoked("child1-jti"), "Child1 should NOT be revoked")
	assert.True(t, revocationStore.IsRevoked("child2-jti"), "Child2 should be revoked")
	assert.True(t, revocationStore.IsRevoked("grandchild1-jti"), "Grandchild1 should be revoked")
}
