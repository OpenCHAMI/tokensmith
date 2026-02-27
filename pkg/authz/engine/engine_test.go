package engine

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/openchami/tokensmith/internal/casbinfuncs"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/authz/presets"
)

func TestBuilder_Build_RegistersRequiredFunctionsFromPreset(t *testing.T) {
	b := NewBuilder().
		WithModelPreset(presets.RBACKeyMatch2REST()).
		WithPolicyPath("").
		WithGroupingPath("")

	a, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.PolicyVersion() == "" {
		t.Fatalf("expected policy version")
	}

	// Baseline policy grants role:viewer read access to metadata:nodes.
	p := authz.Principal{ID: "alice", Roles: []string{"viewer"}}
	dec, _ := a.Authorize(context.Background(), p, "metadata:nodes", "read")
	if dec != authz.DecisionAllow {
		t.Fatalf("expected allow, got %s", dec)
	}
}

func TestBuilder_EnforcerHook_RunsDuringBuild(t *testing.T) {
	var calls atomic.Int32

	b := NewBuilder().
		WithModelPreset(presets.RBACBasic()).
		WithPolicyPath("").
		WithGroupingPath("")

	b.WithCasbinEnforcerHook(func(e *casbin.Enforcer) error {
		calls.Add(1)
		return nil
	})

	_, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected hook called once, got %d", calls.Load())
	}
}

func TestBuilder_EnforcerHook_CanAddCustomMatcherFunction(t *testing.T) {
	var hookCalls atomic.Int32

	b := NewBuilder().
		WithModelText(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && startsWith(r.obj, p.obj) && r.act == p.act
`).
		WithPolicyPath("").
		WithGroupingPath("")

	b.WithCasbinEnforcerHook(func(e *casbin.Enforcer) error {
		hookCalls.Add(1)
		e.AddFunction("startsWith", func(args ...any) (any, error) {
			a0, _ := args[0].(string)
			a1, _ := args[1].(string)
			return strings.HasPrefix(a0, a1), nil
		})
		_, _ = e.AddPolicy("role:viewer", "/v1/nodes", "read")
		return nil
	})

	a, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if hookCalls.Load() != 1 {
		t.Fatalf("expected hook called once, got %d", hookCalls.Load())
	}

	p := authz.Principal{ID: "alice", Roles: []string{"viewer"}}
	dec, _ := a.Authorize(context.Background(), p, "/v1/nodes/123", "read")
	if dec != authz.DecisionAllow {
		t.Fatalf("expected allow, got %s", dec)
	}
}

func TestBuilder_RequiredFunctions_Registers(t *testing.T) {
	b := NewBuilder().
		WithModelPreset(presets.RBACKeyMatch2REST()).
		WithRequiredFunctions(casbinfuncs.FuncRegexMatch).
		WithPolicyPath("")

	_, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
}
