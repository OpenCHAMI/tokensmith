package casbinfuncs

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/require"
)

func TestRequire_RegistersKnownFunctions(t *testing.T) {
	m, err := model.NewModelFromString(`[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
`)
	require.NoError(t, err)

	e, err := casbin.NewEnforcer(m)
	require.NoError(t, err)

	err = Require(e, FuncKeyMatch2, FuncRegexMatch)
	require.NoError(t, err)

	ok, err := e.Enforce("u", "/foo/123", "+")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestRequire_UnknownFunction(t *testing.T) {
	m, err := model.NewModelFromString(`[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.obj == p.obj
`)
	require.NoError(t, err)

	e, err := casbin.NewEnforcer(m)
	require.NoError(t, err)

	err = Require(e, Name("nope"))
	require.Error(t, err)
}
