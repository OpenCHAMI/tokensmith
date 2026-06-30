// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/keys"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCreationWithParent_IntegrationTest(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	tokenManager := token.NewTokenManager(keyManager, "test-issuer", "test-cluster", "test-openchami", false)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "parent-jti-abc",
			Issuer:    "test-issuer",
			Audience:  []string{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		AMR:       []string{"pwd", "otp"},
		ACR:       "urn:mfa:required",
		AuthTime:  time.Now().Unix(),
		SessionID: "sess-xyz789",
		Scope:     []string{"read", "write", "delete"},
	}

	parentToken, err := tokenManager.GenerateToken(parentClaims)
	require.NoError(t, err)
	assert.NotEmpty(t, parentToken)

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "child-jti-def",
			Issuer:    "test-issuer",
			Audience:  []string{"test-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		Scope: []string{"read"},
	}

	validator := NewHierarchyValidator(newMockHierarchyStorage())

	result, err := validator.ValidateAndInheritClaims(context.Background(), ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, []string{"pwd", "otp"}, childClaims.AMR, "Child should inherit AMR from parent")
	assert.Equal(t, "urn:mfa:required", childClaims.ACR, "Child should inherit ACR from parent")
	assert.Equal(t, parentClaims.AuthTime, childClaims.AuthTime, "Child should inherit auth_time from parent")
	assert.Equal(t, "sess-xyz789", childClaims.SessionID, "Child should inherit session_id from parent")
	assert.Equal(t, "parent-jti-abc", childClaims.ParentID, "Child should have parent_id set")

	assert.Equal(t, []string{"read"}, childClaims.Scope, "Child scopes should be subset of parent")

	assert.Equal(t, 1, result.Depth, "Child token should be at depth 1")
	assert.Equal(t, []string{"pwd", "otp"}, result.InheritedClaims.AMR)
	assert.Equal(t, "urn:mfa:required", result.InheritedClaims.ACR)
	assert.Equal(t, parentClaims.AuthTime, result.InheritedClaims.AuthTime)
	assert.Equal(t, "sess-xyz789", result.InheritedClaims.SessionID)
	assert.Equal(t, []string{"read", "write", "delete"}, result.InheritedClaims.ParentScopes)

	childToken, err := tokenManager.GenerateToken(childClaims)
	require.NoError(t, err)
	assert.NotEmpty(t, childToken)

	parsedChildClaims, _, err := tokenManager.ParseToken(childToken)
	require.NoError(t, err)

	assert.Equal(t, []string{"pwd", "otp"}, parsedChildClaims.AMR)
	assert.Equal(t, "urn:mfa:required", parsedChildClaims.ACR)
	assert.Equal(t, parentClaims.AuthTime, parsedChildClaims.AuthTime)
	assert.Equal(t, "sess-xyz789", parsedChildClaims.SessionID)
	assert.Equal(t, "parent-jti-abc", parsedChildClaims.ParentID)

	t.Log("✅ Integration test passed: Child token successfully inherits MFA claims from parent")
}

func TestTokenCreationWithParent_PreventElevation(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "parent-jti-abc",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		AMR:   []string{"pwd"},
		Scope: []string{"read"},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "child-jti-def",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
		AMR:   []string{"pwd", "otp"},
		Scope: []string{"read", "write"},
	}

	validator := NewHierarchyValidator(newMockHierarchyStorage())

	_, err = validator.ValidateAndInheritClaims(context.Background(), ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	})
	assert.ErrorIs(t, err, ErrClaimElevation, "Should prevent child from adding AMR values not in parent")
}

func TestTokenCreationWithParent_ThreeGenerationHierarchy(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyManager := keys.NewKeyManager()
	err = keyManager.SetKeyPair(privateKey, &privateKey.PublicKey)
	require.NoError(t, err)

	tokenManager := token.NewTokenManager(keyManager, "test-issuer", "test-cluster", "test-openchami", false)
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	rootClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "root-jti",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Hour)),
		},
		AMR:       []string{"pwd", "otp", "fido2"},
		ACR:       "urn:mfa:required",
		AuthTime:  time.Now().Unix(),
		SessionID: "sess-root",
		Scope:     []string{"read", "write", "delete", "admin"},
	}

	rootToken, err := tokenManager.GenerateToken(rootClaims)
	require.NoError(t, err)

	child1Claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "child1-jti",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
		},
		Scope: []string{"read", "write"},
	}

	result1, err := validator.ValidateAndInheritClaims(context.Background(), ClaimInheritanceRequest{
		ParentClaims: rootClaims,
		ChildClaims:  child1Claims,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result1.Depth)

	storage.addHierarchy(&TokenHierarchy{
		ParentTokenID: "root-jti",
		ChildTokenID:  "child1-jti",
		Depth:         1,
	})

	child1Token, err := tokenManager.GenerateToken(child1Claims)
	require.NoError(t, err)

	child2Claims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-123",
			ID:        "child2-jti",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		},
		Scope: []string{"read"},
	}

	result2, err := validator.ValidateAndInheritClaims(context.Background(), ClaimInheritanceRequest{
		ParentClaims: child1Claims,
		ChildClaims:  child2Claims,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result2.Depth, "Grandchild should be at depth 2")

	assert.Equal(t, []string{"pwd", "otp", "fido2"}, child2Claims.AMR, "Grandchild inherits AMR from parent (child1)")
	assert.Equal(t, "urn:mfa:required", child2Claims.ACR)
	assert.Equal(t, rootClaims.AuthTime, child2Claims.AuthTime, "Grandchild inherits original auth_time from root")
	assert.Equal(t, "sess-root", child2Claims.SessionID)
	assert.Equal(t, "child1-jti", child2Claims.ParentID)

	child2Token, err := tokenManager.GenerateToken(child2Claims)
	require.NoError(t, err)

	t.Logf("✅ Three-generation hierarchy:")
	t.Logf("   Root: %s (depth 0)", rootToken[:20])
	t.Logf("   Child1: %s (depth 1)", child1Token[:20])
	t.Logf("   Child2: %s (depth 2)", child2Token[:20])
}
