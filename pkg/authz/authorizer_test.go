package authz

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

const testModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func newTestAuthorizer(t *testing.T, policyVersion string, cacheSize int) *Authorizer {
	t.Helper()
	m, err := model.NewModelFromString(testModel)
	if err != nil {
		t.Fatalf("model parse: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	// role mapping and a single permission
	_, _ = e.AddGroupingPolicy("user:alice", "role:viewer")
	_, _ = e.AddPolicy("role:viewer", "metadata:nodes", "read")

	a, err := NewAuthorizer(e, policyVersion, WithDecisionCache(cacheSize))
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	return a
}

func TestAuthorize_CacheBounded_LRUEviction(t *testing.T) {
	a := newTestAuthorizer(t, "pv1", 2)
	p := Principal{ID: "alice", Roles: []string{"viewer"}}

	// Fill cache with two distinct decisions.
	a.Authorize(context.Background(), p, "metadata:nodes", "read")
	a.Authorize(context.Background(), p, "metadata:nodes", "update")

	// Touch the first key again so it's most recently used.
	_, r := a.Authorize(context.Background(), p, "metadata:nodes", "read")
	if !r.Cached {
		// first time might not be cached depending on ordering; call again to ensure.
		_, r = a.Authorize(context.Background(), p, "metadata:nodes", "read")
	}
	if !r.Cached {
		t.Fatalf("expected cached=true after repeated authorize")
	}

	// Add third distinct key; should evict the LRU (update), keeping (read).
	a.Authorize(context.Background(), p, "metadata:nodes", "delete")

	// (read) should still be cached.
	_, r = a.Authorize(context.Background(), p, "metadata:nodes", "read")
	if !r.Cached {
		t.Fatalf("expected read to remain cached")
	}

	// (update) should have been evicted.
	_, r = a.Authorize(context.Background(), p, "metadata:nodes", "update")
	if r.Cached {
		t.Fatalf("expected update to be evicted from cache")
	}
}

func TestAuthorize_CacheInvalidatedByPolicyVersion(t *testing.T) {
	p := Principal{ID: "alice", Roles: []string{"viewer"}}
	a1 := newTestAuthorizer(t, "pv1", 10)
	a2 := newTestAuthorizer(t, "pv2", 10)

	_, r1 := a1.Authorize(context.Background(), p, "metadata:nodes", "read")
	if r1.Cached {
		t.Fatalf("expected first decision not cached")
	}
	_, r1 = a1.Authorize(context.Background(), p, "metadata:nodes", "read")
	if !r1.Cached {
		t.Fatalf("expected second decision cached")
	}

	// Different policy version should not see cached=true.
	_, r2 := a2.Authorize(context.Background(), p, "metadata:nodes", "read")
	if r2.Cached {
		t.Fatalf("expected cache miss under different policy version")
	}
}

func TestAuthorize_RolesHashAffectsCacheKey(t *testing.T) {
	a := newTestAuthorizer(t, "pv1", 10)

	p1 := Principal{ID: "alice", Roles: []string{"viewer"}}
	p2 := Principal{ID: "alice", Roles: []string{"viewer", "operator"}}

	_, r := a.Authorize(context.Background(), p1, "metadata:nodes", "read")
	if r.Cached {
		t.Fatalf("expected cache miss")
	}
	_, r = a.Authorize(context.Background(), p1, "metadata:nodes", "read")
	if !r.Cached {
		t.Fatalf("expected cache hit")
	}

	_, r = a.Authorize(context.Background(), p2, "metadata:nodes", "read")
	if r.Cached {
		t.Fatalf("expected cache miss because roles changed")
	}
}
