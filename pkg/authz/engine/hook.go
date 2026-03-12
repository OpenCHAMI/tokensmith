// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package engine

import (
	"fmt"

	"github.com/casbin/casbin/v2"
)

// EnforcerHook is an escape hatch to mutate the Casbin enforcer during
// construction.
//
// IMPORTANT:
//   - The hook runs only during Builder.Build.
//   - After Build returns successfully, the enforcer must be treated as
//     immutable. Do not mutate policy or functions at runtime.
//
// This hook is defined in a subpackage so most TokenSmith consumers do not need
// Casbin imports.
//
// See docs/authz_policy.md.
//
//nolint:revive // name chosen intentionally
type EnforcerHook func(e *casbin.Enforcer) error

type hookWrapper struct {
	fn EnforcerHook
}

func (h hookWrapper) apply(e *casbin.Enforcer) error {
	if h.fn == nil {
		return nil
	}
	if err := h.fn(e); err != nil {
		return fmt.Errorf("casbin enforcer hook: %w", err)
	}
	return nil
}

// WithCasbinEnforcerHook installs an escape hatch hook that will run during
// Builder.Build.
func (b *Builder) WithCasbinEnforcerHook(fn EnforcerHook) *Builder {
	b.hook = hookWrapper{fn: fn}
	return b
}
