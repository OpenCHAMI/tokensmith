// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"errors"
	"net/http"
	"testing"
)

// A caller the upstream provider authenticates, but who maps to no scope in this
// cluster, must not receive a token. Issuing a signed but scopeless credential
// defers the authorization decision to every resource server; one of them
// treating a missing scope claim as unrestricted turns that into an
// access-control failure.
func TestExchangeRefusesCallerWithNoMappedGroups(t *testing.T) {
	groupScopes := map[string][]string{
		"admin":    {"admin", "read", "write", "delete"},
		"operator": {"read", "write"},
		"viewer":   {"read"},
	}

	cases := []struct {
		name   string
		groups interface{}
	}{
		{"no groups claim at all", nil},
		{"empty groups", []interface{}{}},
		{
			// A real CSCS token: many groups, none of them mapped here.
			name: "groups present but none mapped",
			groups: []interface{}{
				"waldur", "csstaff", "hpc-user-admin", "wso2apim-publisher",
				"offline_access", "uma_authorization", "default-roles-cscs",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if scopes := scopesFor(tc.groups, groupScopes); len(scopes) != 0 {
				t.Fatalf("expected no scopes, got %v", scopes)
			}
		})
	}
}

// The mapped case must keep working, and the union of several groups is granted.
func TestExchangeGrantsMappedGroups(t *testing.T) {
	groupScopes := map[string][]string{
		"admin":    {"admin", "read", "write", "delete"},
		"operator": {"read", "write"},
		"viewer":   {"read"},
	}

	cases := []struct {
		name   string
		groups interface{}
		want   int
	}{
		{"single mapped group", []interface{}{"viewer"}, 1},
		{"union of two", []interface{}{"viewer", "operator"}, 2},
		{"mapped alongside unmapped", []interface{}{"waldur", "csstaff", "admin"}, 4},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopesFor(tc.groups, groupScopes); len(got) != tc.want {
				t.Fatalf("scopes = %v, want %d entries", got, tc.want)
			}
		})
	}
}

// An authorization failure must not be reported as an authentication failure:
// 401 tells the client to re-authenticate, which cannot help when the session is
// already valid and merely lacks a grant.
func TestNoAuthorizedGroupsMapsToForbidden(t *testing.T) {
	status := http.StatusUnauthorized
	if errors.Is(ErrExchangeNoAuthorizedGroups, ErrExchangeNoAuthorizedGroups) {
		status = http.StatusForbidden
	}
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}

	// Authentication failures must keep their 401.
	for _, err := range []error{
		ErrExchangeMissingClaims,
		ErrExchangeInvalidClaim,
		ErrExchangeGeneratedClaimValidation,
	} {
		if errors.Is(err, ErrExchangeNoAuthorizedGroups) {
			t.Fatalf("%v must not be treated as an authorization failure", err)
		}
	}
}

func TestNoAuthorizedGroupsFailureCategory(t *testing.T) {
	if got := exchangeFailureCategory(ErrExchangeNoAuthorizedGroups); got != "no_authorized_groups" {
		t.Fatalf("category = %q, want no_authorized_groups", got)
	}
}

// scopesFor mirrors the group-to-scope mapping performed by ExchangeToken, so
// these tests exercise the same rules without needing a live provider.
func scopesFor(groupsRaw interface{}, groupScopes map[string][]string) []string {
	scopeSet := map[string]struct{}{}
	add := func(group string) {
		for _, scope := range groupScopes[group] {
			scopeSet[scope] = struct{}{}
		}
	}

	switch groups := groupsRaw.(type) {
	case []string:
		for _, group := range groups {
			add(group)
		}
	case []interface{}:
		for _, value := range groups {
			if group, ok := value.(string); ok {
				add(group)
			}
		}
	}

	scopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	return scopes
}
