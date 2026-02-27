// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package engine constructs a Casbin-backed Authorizer.
//
// TokenSmith is Casbin-first: services and operators should interact with Casbin
// model/policy files directly. This package provides convenience wiring:
//   - policy loading/versioning via pkg/authz/policyloader
//   - matcher helper registration via internal/casbinfuncs
//   - a construction-time-only enforcer hook (escape hatch)
package engine

import (
	"fmt"

	"github.com/openchami/tokensmith/internal/casbinfuncs"
	"github.com/openchami/tokensmith/pkg/authz"
	"github.com/openchami/tokensmith/pkg/authz/policyloader"
	"github.com/openchami/tokensmith/pkg/authz/presets"
)

// Builder constructs an authz.Authorizer from Casbin artifacts.
//
// The returned Authorizer is safe for concurrent use.
//
// IMPORTANT: Casbin enforcers are mutable. To avoid thread-safety surprises,
// TokenSmith only exposes an escape hatch hook that runs during construction.
// After Build returns successfully, the enforcer must be treated as immutable.
// Do not add/remove policies or functions at runtime.
type Builder struct {
	loader *policyloader.Loader

	modelText string
	modelPath string
	preset    *presets.ModelPreset

	policyPath   string
	groupingPath string

	requiredFuncs []casbinfuncs.Name
	hook          hookWrapper

	authorizerOpts []authz.AuthorizerOption
}

// NewBuilder returns a new Builder.
func NewBuilder() *Builder {
	return &Builder{loader: policyloader.New()}
}

// WithModelText sets the model.conf text.
func (b *Builder) WithModelText(text string) *Builder {
	b.modelText = text
	b.modelPath = ""
	b.preset = nil
	b.requiredFuncs = nil
	return b
}

// WithModelPath sets the model.conf file path.
func (b *Builder) WithModelPath(path string) *Builder {
	b.modelPath = path
	b.modelText = ""
	b.preset = nil
	b.requiredFuncs = nil
	return b
}

// WithModelPreset sets a model preset (convenience).
func (b *Builder) WithModelPreset(p presets.ModelPreset) *Builder {
	b.preset = &p
	b.modelText = ""
	b.modelPath = ""
	b.requiredFuncs = append([]casbinfuncs.Name(nil), p.RequiredFunctions...)
	return b
}

// WithPolicyPath sets the policy source (file or directory).
func (b *Builder) WithPolicyPath(path string) *Builder {
	b.policyPath = path
	return b
}

// WithGroupingPath sets the grouping policy source (file or directory).
func (b *Builder) WithGroupingPath(path string) *Builder {
	b.groupingPath = path
	return b
}

// WithRequiredFunctions adds matcher helper functions to register.
//
// This is primarily used for non-preset models that require helpers like
// keyMatch2.
func (b *Builder) WithRequiredFunctions(names ...casbinfuncs.Name) *Builder {
	b.requiredFuncs = append(b.requiredFuncs, names...)
	return b
}

// WithAuthorizerOptions passes options through to authz.NewAuthorizer.
func (b *Builder) WithAuthorizerOptions(opts ...authz.AuthorizerOption) *Builder {
	b.authorizerOpts = append(b.authorizerOpts, opts...)
	return b
}

// Build loads policy artifacts, registers matcher helper functions, executes the
// optional hook, and returns a Casbin-backed authz.Authorizer.
func (b *Builder) Build() (*authz.Authorizer, error) {
	if b == nil {
		return nil, fmt.Errorf("builder is nil")
	}
	if b.loader == nil {
		b.loader = policyloader.New()
	}

	var src policyloader.Source
	switch {
	case b.preset != nil:
		src.ModelText = b.preset.ModelText
	case b.modelText != "":
		src.ModelText = b.modelText
	case b.modelPath != "":
		src.ModelPath = b.modelPath
	default:
		return nil, fmt.Errorf("model not specified")
	}
	src.PolicyPath = b.policyPath
	src.GroupingPath = b.groupingPath

	e, err := b.loader.LoadSource(src)
	if err != nil {
		return nil, err
	}

	if err := casbinfuncs.Require(e, b.requiredFuncs...); err != nil {
		return nil, err
	}

	if err := b.hook.apply(e); err != nil {
		return nil, err
	}

	pv := b.loader.PolicyVersion()
	if pv == "" {
		return nil, fmt.Errorf("policy version not set")
	}
	return authz.NewAuthorizer(e, pv, b.authorizerOpts...)
}
