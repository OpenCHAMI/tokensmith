// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openchami/tokensmith/pkg/token"
)

const (
	MaxHierarchyDepth = 5
)

var (
	ErrCircularReference   = errors.New("circular reference detected in token hierarchy")
	ErrMaxDepthExceeded    = errors.New("maximum hierarchy depth exceeded")
	ErrClaimElevation      = errors.New("child token cannot elevate claims beyond parent")
	ErrSubjectMismatch     = errors.New("child and parent tokens must have the same subject")
	ErrParentTokenNotFound = errors.New("parent token not found")
	ErrParentTokenExpired  = errors.New("parent token has expired")
	ErrParentTokenRevoked  = errors.New("parent token has been revoked")
)

type InheritedClaims struct {
	AMR          []string
	ACR          string
	AuthTime     int64
	SessionID    string
	ParentScopes []string
}

type TokenHierarchy struct {
	ParentTokenID   string
	ChildTokenID    string
	Subject         string
	InheritedClaims InheritedClaims
	Depth           int
}

type HierarchyValidator struct {
	storage TokenHierarchyStorage
}

type TokenHierarchyStorage interface {
	GetHierarchyByChildID(ctx context.Context, childID string) (*TokenHierarchy, error)
	ListHierarchiesByParentID(ctx context.Context, parentID string) ([]*TokenHierarchy, error)
}

func NewHierarchyValidator(storage TokenHierarchyStorage) *HierarchyValidator {
	return &HierarchyValidator{
		storage: storage,
	}
}

type ClaimInheritanceRequest struct {
	ParentClaims *token.TSClaims
	ChildClaims  *token.TSClaims
}

type ClaimInheritanceResult struct {
	InheritedClaims InheritedClaims
	Depth           int
}

func (h *HierarchyValidator) ValidateAndInheritClaims(ctx context.Context, req ClaimInheritanceRequest) (*ClaimInheritanceResult, error) {
	if req.ParentClaims.Subject != req.ChildClaims.Subject {
		return nil, fmt.Errorf("%w: parent=%s, child=%s", ErrSubjectMismatch, req.ParentClaims.Subject, req.ChildClaims.Subject)
	}

	if err := h.detectCircularReference(ctx, req.ParentClaims.ID, req.ChildClaims.ID); err != nil {
		return nil, err
	}

	depth, err := h.calculateDepth(ctx, req.ParentClaims.ID)
	if err != nil {
		return nil, err
	}

	if depth >= MaxHierarchyDepth {
		return nil, fmt.Errorf("%w: current depth=%d, max=%d", ErrMaxDepthExceeded, depth, MaxHierarchyDepth)
	}

	if err := validateClaimDegradation(req.ParentClaims, req.ChildClaims); err != nil {
		return nil, err
	}

	inheritedClaims := InheritedClaims{
		AMR:          req.ParentClaims.AMR,
		ACR:          req.ParentClaims.ACR,
		AuthTime:     req.ParentClaims.AuthTime,
		SessionID:    req.ParentClaims.SessionID,
		ParentScopes: req.ParentClaims.Scope,
	}

	req.ChildClaims.AMR = req.ParentClaims.AMR
	req.ChildClaims.ACR = req.ParentClaims.ACR
	req.ChildClaims.AuthTime = req.ParentClaims.AuthTime
	req.ChildClaims.SessionID = req.ParentClaims.SessionID
	req.ChildClaims.ParentID = req.ParentClaims.ID

	return &ClaimInheritanceResult{
		InheritedClaims: inheritedClaims,
		Depth:           depth + 1,
	}, nil
}

func (h *HierarchyValidator) detectCircularReference(ctx context.Context, candidateParentID, candidateChildID string) error {
	current := candidateParentID
	visited := make(map[string]bool)

	for current != "" {
		if current == candidateChildID {
			return ErrCircularReference
		}

		if visited[current] {
			return ErrCircularReference
		}
		visited[current] = true

		hierarchy, err := h.storage.GetHierarchyByChildID(ctx, current)
		if err != nil {
			break
		}

		current = hierarchy.ParentTokenID
	}

	return nil
}

func (h *HierarchyValidator) calculateDepth(ctx context.Context, tokenID string) (int, error) {
	depth := 0
	current := tokenID

	for current != "" {
		hierarchy, err := h.storage.GetHierarchyByChildID(ctx, current)
		if err != nil {
			break
		}

		depth++
		if depth > MaxHierarchyDepth {
			return depth, ErrMaxDepthExceeded
		}

		current = hierarchy.ParentTokenID
	}

	return depth, nil
}

func validateClaimDegradation(parent, child *token.TSClaims) error {
	if err := validateAMRElevation(parent.AMR, child.AMR); err != nil {
		return err
	}

	if err := validateScopeElevation(parent.Scope, child.Scope); err != nil {
		return err
	}

	return nil
}

func validateAMRElevation(parentAMR, childAMR []string) error {
	if len(childAMR) == 0 {
		return nil
	}

	parentSet := make(map[string]bool)
	for _, amr := range parentAMR {
		parentSet[amr] = true
	}

	for _, amr := range childAMR {
		if !parentSet[amr] {
			return fmt.Errorf("%w: child has AMR value '%s' not present in parent AMR %v", ErrClaimElevation, amr, parentAMR)
		}
	}

	return nil
}

func validateScopeElevation(parentScopes, childScopes []string) error {
	if len(childScopes) == 0 {
		return nil
	}

	parentSet := make(map[string]bool)
	for _, scope := range parentScopes {
		parentSet[scope] = true
	}

	for _, scope := range childScopes {
		if !parentSet[scope] {
			return fmt.Errorf("%w: child has scope '%s' not present in parent scopes %v", ErrClaimElevation, scope, parentScopes)
		}
	}

	return nil
}

func (h *HierarchyValidator) ValidateParentToken(parentClaims *token.TSClaims, now time.Time) error {
	if parentClaims.ExpiresAt != nil && now.After(parentClaims.ExpiresAt.Time) {
		return ErrParentTokenExpired
	}

	return nil
}
