// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package casbinfuncs provides a centralized registry of Casbin matcher
// functions used by TokenSmith model presets.
//
// This is internal by design: services should interact with Casbin via
// model/policy files. TokenSmith uses this registry to ensure the same named
// functions are wired consistently across presets.
package casbinfuncs

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
)

// Name is the canonical identifier for a matcher helper.
type Name string

const (
	FuncKeyMatch   Name = "keyMatch"
	FuncKeyMatch2  Name = "keyMatch2"
	FuncRegexMatch Name = "regexMatch"
)

// Require registers the requested Casbin function names on the enforcer.
//
// It is safe to call multiple times; the last registration wins.
func Require(e *casbin.Enforcer, names ...Name) error {
	if e == nil {
		return fmt.Errorf("casbin enforcer is nil")
	}
	for _, n := range names {
		switch n {
		case FuncKeyMatch:
			e.AddFunction(string(FuncKeyMatch), util.KeyMatchFunc)
		case FuncKeyMatch2:
			e.AddFunction(string(FuncKeyMatch2), util.KeyMatch2Func)
		case FuncRegexMatch:
			e.AddFunction(string(FuncRegexMatch), util.RegexMatchFunc)
		default:
			return fmt.Errorf("unknown casbin function %q", n)
		}
	}
	return nil
}
