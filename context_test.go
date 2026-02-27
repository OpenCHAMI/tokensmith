package tokensmith

import (
	"context"
	"testing"

	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/token"
)

func TestPrincipalFromContext_ReadNewPreferred(t *testing.T) {
	want := &authz.Principal{ID: "u1", Roles: []string{"r1"}}
	ctx := SetPrincipal(context.Background(), want)

	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected ok")
	}
	if got.ID != want.ID {
		t.Fatalf("id=%q want %q", got.ID, want.ID)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "r1" {
		t.Fatalf("roles=%v want %v", got.Roles, want.Roles)
	}
}

func TestPrincipalFromContext_FallsBackToLegacyClaims(t *testing.T) {
	claims := &token.TSClaims{}
	claims.Subject = "legacy-sub"
	claims.Scope = []string{"role1", "role2"}

	ctx := context.WithValue(context.Background(), legacyClaimsContextKey, claims)

	got, ok := PrincipalFromContext(ctx)
	if !ok {
		t.Fatalf("expected ok")
	}
	if got.ID != "legacy-sub" {
		t.Fatalf("id=%q want %q", got.ID, "legacy-sub")
	}
	if len(got.Roles) != 2 || got.Roles[0] != "role1" || got.Roles[1] != "role2" {
		t.Fatalf("roles=%v", got.Roles)
	}
}

func TestPrincipalFromContext_NoPrincipalNoClaims(t *testing.T) {
	_, ok := PrincipalFromContext(context.Background())
	if ok {
		t.Fatalf("expected !ok")
	}
}
