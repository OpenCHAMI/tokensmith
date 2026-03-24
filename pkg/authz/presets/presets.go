// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package presets provides convenience Casbin model presets.
//
// TokenSmith is Casbin-first: the external interface is the Casbin model/policy
// files. Presets are only helpers that return model.conf text plus a list of
// required matcher functions.
package presets

import "github.com/openchami/tokensmith/internal/casbinfuncs"

// ModelPreset describes a Casbin model preset.
//
// Services can use the returned ModelText to create an enforcer and must ensure
// RequiredFunctions are registered (TokenSmith does this when using presets).
//
// Domains indicates whether the model expects a domain field (RBAC with
// domains).
type ModelPreset struct {
	ModelText         string
	RequiredFunctions []casbinfuncs.Name
	Domains           bool
}

// RBACBasic returns a simple RBAC model using sub,obj,act with equality match.
func RBACBasic() ModelPreset {
	return ModelPreset{
		ModelText: rbacBasicModel,
		Domains:   false,
	}
}

// RBACKeyMatch2REST returns an RBAC model using sub,obj,act where obj is a URL
// path matched via keyMatch2.
func RBACKeyMatch2REST() ModelPreset {
	return ModelPreset{
		ModelText:         rbacKeyMatch2RESTModel,
		RequiredFunctions: []casbinfuncs.Name{casbinfuncs.FuncKeyMatch2},
		Domains:           false,
	}
}

// RBACWithDomains returns RBAC with domains using sub,dom,obj,act with equality
// match.
func RBACWithDomains() ModelPreset {
	return ModelPreset{
		ModelText: rbacWithDomainsModel,
		Domains:   true,
	}
}

// RBACDomainsKeyMatch2REST returns RBAC with domains using keyMatch2 for obj.
func RBACDomainsKeyMatch2REST() ModelPreset {
	return ModelPreset{
		ModelText:         rbacDomainsKeyMatch2RESTModel,
		RequiredFunctions: []casbinfuncs.Name{casbinfuncs.FuncKeyMatch2},
		Domains:           true,
	}
}

const rbacBasicModel = `# Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

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

const rbacKeyMatch2RESTModel = `# Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
# obj is expected to be a normalized URL path. keyMatch2 allows patterns like:
#   /v1/nodes/:id
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && r.act == p.act
`

const rbacWithDomainsModel = `# Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

[request_definition]
r = sub, dom, obj, act

[policy_definition]	p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

const rbacDomainsKeyMatch2RESTModel = `# Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
#
# SPDX-License-Identifier: MIT

[request_definition]
r = sub, dom, obj, act

[policy_definition]	p = sub, dom, obj, act

[role_definition]	g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
# obj is expected to be a normalized URL path. keyMatch2 allows patterns like:
#   /v1/nodes/:id
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch2(r.obj, p.obj) && r.act == p.act
`
