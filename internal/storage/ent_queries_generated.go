package storage

import (
	"context"
	"fmt"

	"github.com/openchami/tokensmith/internal/storage/ent"
	"github.com/openchami/tokensmith/internal/storage/ent/label"
	entresource "github.com/openchami/tokensmith/internal/storage/ent/resource"

	v1 "github.com/openchami/tokensmith/apis/tokensmith.openchami.io/v1"
)

// ensureEntClient verifies the ent client has been initialized
func ensureEntClient() {
	if entClient == nil {
		panic("ent client not initialized: call SetEntClient in main.go before using storage")
	}
}

// QueryResources returns a generic query builder for a given kind
func QueryResources(ctx context.Context, kind string) *ent.ResourceQuery {
	ensureEntClient()
	return entClient.Resource.Query().
		Where(entresource.KindEQ(kind))
}

// QueryResourcesByLabels queries resources by kind and exact-match labels
func QueryResourcesByLabels(ctx context.Context, kind string, labels map[string]string) (*ent.ResourceQuery, error) {
	ensureEntClient()
	q := entClient.Resource.Query().Where(entresource.KindEQ(kind))
	for k, v := range labels {
		q = q.Where(entresource.HasLabelsWith(
			label.KeyEQ(k),
			label.ValueEQ(v),
		))
	}
	return q, nil
}

// Querybootstraptokenpolicys returns a query builder for bootstraptokenpolicys
func Querybootstraptokenpolicys(ctx context.Context) *ent.ResourceQuery {
	return QueryResources(ctx, "BootstrapTokenPolicy")
}

// GetBootstrapTokenPolicyByUID loads a single BootstrapTokenPolicy by UID
func GetBootstrapTokenPolicyByUID(ctx context.Context, uid string) (*v1.BootstrapTokenPolicy, error) {
	ensureEntClient()
	r, err := entClient.Resource.Query().
		Where(entresource.UIDEQ(uid), entresource.KindEQ("BootstrapTokenPolicy")).
		WithLabels().
		WithAnnotations().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to load BootstrapTokenPolicy %s: %w", uid, err)
	}
	v, err := FromEntResource(ctx, r)
	if err != nil {
		return nil, err
	}
	return v.(*v1.BootstrapTokenPolicy), nil
}

// ListbootstraptokenpolicysByLabels returns bootstraptokenpolicys matching all provided labels
func ListbootstraptokenpolicysByLabels(ctx context.Context, labels map[string]string) ([]*v1.BootstrapTokenPolicy, error) {
	q, err := QueryResourcesByLabels(ctx, "BootstrapTokenPolicy", labels)
	if err != nil {
		return nil, err
	}
	rs, err := q.WithLabels().WithAnnotations().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*v1.BootstrapTokenPolicy, 0, len(rs))
	for _, r := range rs {
		v, err := FromEntResource(ctx, r)
		if err != nil {
			continue
		}
		out = append(out, v.(*v1.BootstrapTokenPolicy))
	}
	return out, nil
}

// Queryrefreshtokenfamilys returns a query builder for refreshtokenfamilys
func Queryrefreshtokenfamilys(ctx context.Context) *ent.ResourceQuery {
	return QueryResources(ctx, "RefreshTokenFamily")
}

// GetRefreshTokenFamilyByUID loads a single RefreshTokenFamily by UID
func GetRefreshTokenFamilyByUID(ctx context.Context, uid string) (*v1.RefreshTokenFamily, error) {
	ensureEntClient()
	r, err := entClient.Resource.Query().
		Where(entresource.UIDEQ(uid), entresource.KindEQ("RefreshTokenFamily")).
		WithLabels().
		WithAnnotations().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to load RefreshTokenFamily %s: %w", uid, err)
	}
	v, err := FromEntResource(ctx, r)
	if err != nil {
		return nil, err
	}
	return v.(*v1.RefreshTokenFamily), nil
}

// ListrefreshtokenfamilysByLabels returns refreshtokenfamilys matching all provided labels
func ListrefreshtokenfamilysByLabels(ctx context.Context, labels map[string]string) ([]*v1.RefreshTokenFamily, error) {
	q, err := QueryResourcesByLabels(ctx, "RefreshTokenFamily", labels)
	if err != nil {
		return nil, err
	}
	rs, err := q.WithLabels().WithAnnotations().All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*v1.RefreshTokenFamily, 0, len(rs))
	for _, r := range rs {
		v, err := FromEntResource(ctx, r)
		if err != nil {
			continue
		}
		out = append(out, v.(*v1.RefreshTokenFamily))
	}
	return out, nil
}
