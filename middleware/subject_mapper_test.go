package middleware

import (
	"testing"

	"github.com/openchami/tokensmith/pkg/token"
	"github.com/stretchr/testify/assert"
)

func TestDefaultSubjectMapper_NilClaims(t *testing.T) {
	res := defaultSubjectMapper(nil, nil)
	assert.Nil(t, res)
}

func TestDefaultSubjectMapper_TSClaimsSubject(t *testing.T) {
	c := &token.TSClaims{RegisteredClaims: token.NewClaims().RegisteredClaims}
	c.Subject = "alice"
	res := defaultSubjectMapper(nil, c)
	assert.Equal(t, []string{"user:alice"}, res)
}

func TestDefaultSubjectMapper_RealmAccessRoles(t *testing.T) {
	m := map[string]interface{}{
		"realm_access": map[string]interface{}{
			"roles": []interface{}{"admin", "operator"},
		},
	}
	res := defaultSubjectMapper(nil, m)
	// Order preserved from input
	assert.Equal(t, []string{"role:admin", "role:operator"}, res)
}

func TestDefaultSubjectMapper_RolesClaim(t *testing.T) {
	m := map[string]interface{}{
		"roles": []interface{}{"user", "viewer"},
	}
	res := defaultSubjectMapper(nil, m)
	assert.Equal(t, []string{"role:user", "role:viewer"}, res)
}

func TestDefaultSubjectMapper_MissingRolesFallbackToSub(t *testing.T) {
	m := map[string]interface{}{
		"realm_access": map[string]interface{}{},
		"roles":        []interface{}{},
		"sub":          "bob",
	}
	res := defaultSubjectMapper(nil, m)
	assert.Equal(t, []string{"user:bob"}, res)
}
