package middleware

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCreateEnforcer_LoadsCanonicalPolicy(t *testing.T) {
	// Set env vars to point to the canonical files added to the repo root
	modelPath := filepath.Join("..", "casbin_model.conf")
	policyPath := filepath.Join("..", "casbin_policy.csv")
	t.Setenv(EnvCasbinModelPath, modelPath)
	t.Setenv(EnvCasbinPolicyPath, policyPath)

	enf, err := CreateEnforcer(context.Background(), &EnforcerOptions{FailFast: true})
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	// role:admin should be allowed to POST to boot any node
	if ok, _ := enf.Enforce("role:admin", "/clusters/clusterA/nodes/node123/boot", "post"); !ok {
		t.Fatal("expected role:admin to be allowed to boot nodes")
	}

	// role:operator should be allowed to GET node info
	if ok, _ := enf.Enforce("role:operator", "/clusters/clusterA/nodes/node123", "get"); !ok {
		t.Fatal("expected role:operator to be allowed to get node info")
	}

	// user:alice should be allowed to boot specific node per user override
	if ok, _ := enf.Enforce("user:alice", "/clusters/clusterA/nodes/node123/boot", "post"); !ok {
		t.Fatal("expected user:alice to be allowed to boot node123 in clusterA")
	}

	// user:bob should inherit role:user and be able to GET clusters
	if ok, _ := enf.Enforce("user:bob", "/clusters/clusterA", "get"); !ok {
		t.Fatal("expected user:bob to be allowed to get cluster info via role:user")
	}
}
