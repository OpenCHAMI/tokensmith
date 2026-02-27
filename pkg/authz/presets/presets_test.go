package presets

import (
	"strings"
	"testing"

	"github.com/openchami/tokensmith/internal/casbinfuncs"
	"github.com/stretchr/testify/require"
)

func TestPresets_Basic(t *testing.T) {
	p := RBACBasic()
	require.False(t, p.Domains)
	require.Empty(t, p.RequiredFunctions)
	require.Contains(t, p.ModelText, "[request_definition]")
	require.Contains(t, p.ModelText, "[matchers]")
	require.Contains(t, p.ModelText, "r = sub, obj, act")
	require.Contains(t, p.ModelText, "p = sub, obj, act")
	require.True(t, strings.Contains(p.ModelText, "r.obj == p.obj"))
}

func TestPresets_KeyMatch2REST(t *testing.T) {
	p := RBACKeyMatch2REST()
	require.False(t, p.Domains)
	require.Equal(t, []casbinfuncs.Name{casbinfuncs.FuncKeyMatch2}, p.RequiredFunctions)
	require.Contains(t, p.ModelText, "keyMatch2(")
	require.Contains(t, p.ModelText, "r = sub, obj, act")
}

func TestPresets_WithDomains(t *testing.T) {
	p := RBACWithDomains()
	require.True(t, p.Domains)
	require.Empty(t, p.RequiredFunctions)
	require.Contains(t, p.ModelText, "r = sub, dom, obj, act")
	require.Contains(t, p.ModelText, "p = sub, dom, obj, act")
	require.Contains(t, p.ModelText, "g = _, _, _")
	require.Contains(t, p.ModelText, "r.dom == p.dom")
}

func TestPresets_DomainsKeyMatch2REST(t *testing.T) {
	p := RBACDomainsKeyMatch2REST()
	require.True(t, p.Domains)
	require.Equal(t, []casbinfuncs.Name{casbinfuncs.FuncKeyMatch2}, p.RequiredFunctions)
	require.Contains(t, p.ModelText, "keyMatch2(")
	require.Contains(t, p.ModelText, "r = sub, dom, obj, act")
}
