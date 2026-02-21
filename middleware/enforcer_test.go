package middleware

import (
	"context"
	"os"
	"testing"
)

const sampleModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

const samplePolicy = `p, alice, data1, read
p, bob, data2, write
`

func writeTempFile(t *testing.T, prefix, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", prefix)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	return f.Name()
}

func TestCreateEnforcer_ValidFiles(t *testing.T) {
	model := writeTempFile(t, "model_", sampleModel)
	policy := writeTempFile(t, "policy_", samplePolicy)
	t.Setenv(EnvCasbinModelPath, model)
	t.Setenv(EnvCasbinPolicyPath, policy)
	t.Cleanup(func() {
		if err := os.Remove(model); err != nil {
			t.Errorf("failed to remove model file: %v", err)
		}
		if err := os.Remove(policy); err != nil {
			t.Errorf("failed to remove policy file: %v", err)
		}
	})

	enc, err := CreateEnforcer(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected enforcer, got error: %v", err)
	}
	if ok, _ := enc.Enforce("alice", "data1", "read"); !ok {
		t.Fatal("expected alice to have read on data1")
	}
}

func TestCreateEnforcer_InvalidFiles_FailFast(t *testing.T) {
	t.Setenv(EnvCasbinModelPath, "./nonexistent/model.conf")
	t.Setenv(EnvCasbinPolicyPath, "./nonexistent/policy.csv")

	_, err := CreateEnforcer(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when model/policy missing with fail-fast")
	}
}

func TestCreateEnforcer_InvalidFiles_PermissiveFallback(t *testing.T) {
	t.Setenv(EnvCasbinModelPath, "./nonexistent/model.conf")
	t.Setenv(EnvCasbinPolicyPath, "./nonexistent/policy.csv")

	opts := &EnforcerOptions{FailFast: false, Permissive: true}
	enc, err := CreateEnforcer(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected permissive enforcer, got error: %v", err)
	}
	if ok, _ := enc.Enforce("any", "any", "any"); !ok {
		t.Fatal("expected permissive enforcer to allow request")
	}
}

func TestCreateEnforcer_InvalidFiles_DenyFallback(t *testing.T) {
	t.Setenv(EnvCasbinModelPath, "./nonexistent/model.conf")
	t.Setenv(EnvCasbinPolicyPath, "./nonexistent/policy.csv")

	opts := &EnforcerOptions{FailFast: false, Permissive: false}
	enc, err := CreateEnforcer(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected deny-all enforcer, got error: %v", err)
	}
	if ok, _ := enc.Enforce("any", "any", "any"); ok {
		t.Fatal("expected deny-all enforcer to deny request")
	}
}
