// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openchami/fabrica/pkg/resource"
	v1 "github.com/openchami/tokensmith/apis/tokensmith.openchami.io/v1"
	"github.com/openchami/tokensmith/internal/storage/ent"
	entresource "github.com/openchami/tokensmith/internal/storage/ent/resource"
	"github.com/openchami/tokensmith/pkg/tokenservice"
)

type TokenHierarchyAdapter struct {
	client *ent.Client
}

func NewTokenHierarchyAdapter(client *ent.Client) *TokenHierarchyAdapter {
	return &TokenHierarchyAdapter{client: client}
}

func (a *TokenHierarchyAdapter) GetHierarchyByChildID(ctx context.Context, childID string) (*tokenservice.TokenHierarchy, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ent client not initialized")
	}

	entResources, err := a.client.Resource.Query().
		Where(
			entresource.KindEQ("TokenHierarchy"),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query hierarchy by child ID: %w", err)
	}

	for _, entResource := range entResources {
		var spec v1.TokenHierarchySpec
		if err := json.Unmarshal(entResource.Spec, &spec); err != nil {
			continue
		}

		if spec.ChildTokenID == childID {
			fabricaResource, err := FromEntResource(ctx, entResource)
			if err != nil {
				return nil, fmt.Errorf("failed to convert ent resource: %w", err)
			}

			hierarchy := fabricaResource.(*v1.TokenHierarchy)
			return toTokenServiceHierarchy(hierarchy), nil
		}
	}

	return nil, tokenservice.ErrParentTokenNotFound
}

func (a *TokenHierarchyAdapter) ListHierarchiesByParentID(ctx context.Context, parentID string) ([]*tokenservice.TokenHierarchy, error) {
	if a.client == nil {
		return nil, fmt.Errorf("ent client not initialized")
	}

	entResources, err := a.client.Resource.Query().
		Where(
			entresource.KindEQ("TokenHierarchy"),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to query hierarchies by parent ID: %w", err)
	}

	result := make([]*tokenservice.TokenHierarchy, 0)
	for _, entResource := range entResources {
		var spec v1.TokenHierarchySpec
		if err := json.Unmarshal(entResource.Spec, &spec); err != nil {
			continue
		}

		if spec.ParentTokenID == parentID {
			fabricaResource, err := FromEntResource(ctx, entResource)
			if err != nil {
				return nil, fmt.Errorf("failed to convert ent resource: %w", err)
			}

			hierarchy := fabricaResource.(*v1.TokenHierarchy)
			result = append(result, toTokenServiceHierarchy(hierarchy))
		}
	}

	return result, nil
}

func (a *TokenHierarchyAdapter) SaveHierarchy(ctx context.Context, hierarchy *tokenservice.TokenHierarchy, inheritedClaims *tokenservice.InheritedClaims) error {
	if a.client == nil {
		return fmt.Errorf("ent client not initialized")
	}

	fabricaResource := &v1.TokenHierarchy{
		APIVersion: "tokensmith.openchami.io/v1",
		Kind:       "TokenHierarchy",
		Metadata: resource.Metadata{
			Name: fmt.Sprintf("%s-%s", hierarchy.ParentTokenID[:8], hierarchy.ChildTokenID[:8]),
		},
		Spec: v1.TokenHierarchySpec{
			ParentTokenID: hierarchy.ParentTokenID,
			ChildTokenID:  hierarchy.ChildTokenID,
			Subject:       hierarchy.Subject,
			InheritedClaims: v1.InheritedClaims{
				AMR:          inheritedClaims.AMR,
				ACR:          inheritedClaims.ACR,
				AuthTime:     inheritedClaims.AuthTime,
				SessionID:    inheritedClaims.SessionID,
				ParentScopes: inheritedClaims.ParentScopes,
			},
			CreatedAt: time.Now(),
			Depth:     hierarchy.Depth,
		},
	}

	return SaveTokenHierarchy(ctx, fabricaResource)
}

func toTokenServiceHierarchy(v1Hierarchy *v1.TokenHierarchy) *tokenservice.TokenHierarchy {
	return &tokenservice.TokenHierarchy{
		ParentTokenID: v1Hierarchy.Spec.ParentTokenID,
		ChildTokenID:  v1Hierarchy.Spec.ChildTokenID,
		Subject:       v1Hierarchy.Spec.Subject,
		Depth:         v1Hierarchy.Spec.Depth,
	}
}
