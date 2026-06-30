// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHierarchyStorage struct {
	hierarchies map[string]*TokenHierarchy
}

func newMockHierarchyStorage() *mockHierarchyStorage {
	return &mockHierarchyStorage{
		hierarchies: make(map[string]*TokenHierarchy),
	}
}

func (m *mockHierarchyStorage) GetHierarchyByChildID(ctx context.Context, childID string) (*TokenHierarchy, error) {
	if h, ok := m.hierarchies[childID]; ok {
		return h, nil
	}
	return nil, ErrParentTokenNotFound
}

func (m *mockHierarchyStorage) ListHierarchiesByParentID(ctx context.Context, parentID string) ([]*TokenHierarchy, error) {
	var result []*TokenHierarchy
	for _, h := range m.hierarchies {
		if h.ParentTokenID == parentID {
			result = append(result, h)
		}
	}
	return result, nil
}

func (m *mockHierarchyStorage) addHierarchy(h *TokenHierarchy) {
	m.hierarchies[h.ChildTokenID] = h
}

func TestValidateAndInheritClaims_Success(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "parent-jti",
		},
		AMR:       []string{"pwd", "otp"},
		ACR:       "urn:mfa:required",
		AuthTime:  1719708600,
		SessionID: "sess-xyz",
		Scope:     []string{"read", "write", "delete"},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "child-jti",
		},
		Scope: []string{"read"},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	result, err := validator.ValidateAndInheritClaims(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, []string{"pwd", "otp"}, childClaims.AMR)
	assert.Equal(t, "urn:mfa:required", childClaims.ACR)
	assert.Equal(t, int64(1719708600), childClaims.AuthTime)
	assert.Equal(t, "sess-xyz", childClaims.SessionID)
	assert.Equal(t, "parent-jti", childClaims.ParentID)

	assert.Equal(t, []string{"pwd", "otp"}, result.InheritedClaims.AMR)
	assert.Equal(t, "urn:mfa:required", result.InheritedClaims.ACR)
	assert.Equal(t, int64(1719708600), result.InheritedClaims.AuthTime)
	assert.Equal(t, "sess-xyz", result.InheritedClaims.SessionID)
	assert.Equal(t, []string{"read", "write", "delete"}, result.InheritedClaims.ParentScopes)
	assert.Equal(t, 1, result.Depth)
}

func TestValidateAndInheritClaims_SubjectMismatch(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "parent-jti",
		},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-456",
			ID:      "child-jti",
		},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	_, err := validator.ValidateAndInheritClaims(context.Background(), req)
	assert.ErrorIs(t, err, ErrSubjectMismatch)
}

func TestValidateAndInheritClaims_CircularReference(t *testing.T) {
	storage := newMockHierarchyStorage()

	storage.addHierarchy(&TokenHierarchy{
		ParentTokenID: "token-b",
		ChildTokenID:  "token-a",
	})
	storage.addHierarchy(&TokenHierarchy{
		ParentTokenID: "token-a",
		ChildTokenID:  "token-b",
	})

	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "token-a",
		},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "token-c",
		},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	_, err := validator.ValidateAndInheritClaims(context.Background(), req)
	assert.ErrorIs(t, err, ErrCircularReference)
}

func TestValidateAndInheritClaims_MaxDepthExceeded(t *testing.T) {
	storage := newMockHierarchyStorage()

	current := "root"
	for i := 0; i < MaxHierarchyDepth; i++ {
		next := fmt.Sprintf("token-%d", i)
		storage.addHierarchy(&TokenHierarchy{
			ParentTokenID: current,
			ChildTokenID:  next,
		})
		current = next
	}

	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      current,
		},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "token-new",
		},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	_, err := validator.ValidateAndInheritClaims(context.Background(), req)
	assert.ErrorIs(t, err, ErrMaxDepthExceeded)
}

func TestValidateClaimDegradation_AMRElevationPrevented(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "parent-jti",
		},
		AMR: []string{"pwd"},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "child-jti",
		},
		AMR: []string{"pwd", "otp"},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	_, err := validator.ValidateAndInheritClaims(context.Background(), req)
	assert.ErrorIs(t, err, ErrClaimElevation)
	assert.Contains(t, err.Error(), "otp")
}

func TestValidateClaimDegradation_ScopeElevationPrevented(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "parent-jti",
		},
		Scope: []string{"read"},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "child-jti",
		},
		Scope: []string{"read", "write"},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	_, err := validator.ValidateAndInheritClaims(context.Background(), req)
	assert.ErrorIs(t, err, ErrClaimElevation)
	assert.Contains(t, err.Error(), "write")
}

func TestValidateClaimDegradation_DegradationAllowed(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "parent-jti",
		},
		AMR:   []string{"pwd", "otp", "fido2"},
		Scope: []string{"read", "write", "delete"},
	}

	childClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
			ID:      "child-jti",
		},
		AMR:   []string{"pwd", "otp"},
		Scope: []string{"read"},
	}

	req := ClaimInheritanceRequest{
		ParentClaims: parentClaims,
		ChildClaims:  childClaims,
	}

	result, err := validator.ValidateAndInheritClaims(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, result)

	assert.Equal(t, []string{"pwd", "otp", "fido2"}, childClaims.AMR)
	assert.Equal(t, []string{"read"}, childClaims.Scope)
}

func TestCalculateDepth(t *testing.T) {
	tests := []struct {
		name          string
		setupStorage  func(*mockHierarchyStorage)
		tokenID       string
		expectedDepth int
		expectError   bool
	}{
		{
			name:          "root token (no parent)",
			setupStorage:  func(s *mockHierarchyStorage) {},
			tokenID:       "root-token",
			expectedDepth: 0,
			expectError:   false,
		},
		{
			name: "depth 1 (direct child)",
			setupStorage: func(s *mockHierarchyStorage) {
				s.addHierarchy(&TokenHierarchy{
					ParentTokenID: "root",
					ChildTokenID:  "child-1",
				})
			},
			tokenID:       "child-1",
			expectedDepth: 1,
			expectError:   false,
		},
		{
			name: "depth 3",
			setupStorage: func(s *mockHierarchyStorage) {
				s.addHierarchy(&TokenHierarchy{
					ParentTokenID: "root",
					ChildTokenID:  "child-1",
				})
				s.addHierarchy(&TokenHierarchy{
					ParentTokenID: "child-1",
					ChildTokenID:  "child-2",
				})
				s.addHierarchy(&TokenHierarchy{
					ParentTokenID: "child-2",
					ChildTokenID:  "child-3",
				})
			},
			tokenID:       "child-3",
			expectedDepth: 3,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := newMockHierarchyStorage()
			tt.setupStorage(storage)
			validator := NewHierarchyValidator(storage)

			depth, err := validator.calculateDepth(context.Background(), tt.tokenID)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDepth, depth)
			}
		})
	}
}

func TestValidateParentToken_Expired(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	expiredTime := time.Now().Add(-1 * time.Hour)
	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiredTime),
		},
	}

	err := validator.ValidateParentToken(parentClaims, time.Now())
	assert.ErrorIs(t, err, ErrParentTokenExpired)
}

func TestValidateParentToken_NotExpired(t *testing.T) {
	storage := newMockHierarchyStorage()
	validator := NewHierarchyValidator(storage)

	futureTime := time.Now().Add(1 * time.Hour)
	parentClaims := &token.TSClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(futureTime),
		},
	}

	err := validator.ValidateParentToken(parentClaims, time.Now())
	assert.NoError(t, err)
}
