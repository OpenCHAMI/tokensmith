// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	// EnvAuthzCacheSize configures the maximum number of cached authorization
	// decisions. Cache is disabled by default.
	EnvAuthzCacheSize = "TOKENS_MITH_AUTHZ_CACHE_SIZE"
)

// AuthzResult provides additional details about an authorization decision.
//
// Services may log fields from this struct for troubleshooting.
//
// Note: Policy loading is performed at startup and is not hot-reloaded in v1.
// A restart is required to pick up policy changes.
type AuthzResult struct {
	PolicyVersion string   `json:"policy_version"`
	MatchedRoles  []string `json:"matched_roles,omitempty"`
	Reason        string   `json:"reason"`
	Cached        bool     `json:"cached"`
}

// Authorizer evaluates authorization decisions using Casbin and provides an
// optional bounded LRU cache.
//
// Policy is loaded at startup. Hot reload is not supported in v1.
type Authorizer struct {
	enforcer      *casbin.Enforcer
	policyVersion string

	cacheMu sync.RWMutex
	cache   *lru.Cache[cacheKey, cacheEntry]
}

// NewAuthorizer constructs an Authorizer.
//
// policyVersion MUST be the deterministic policy hash for the effective policy
// set used to create enforcer.
func NewAuthorizer(enforcer *casbin.Enforcer, policyVersion string, opts ...AuthorizerOption) (*Authorizer, error) {
	if enforcer == nil {
		return nil, errors.New("enforcer is nil")
	}
	if strings.TrimSpace(policyVersion) == "" {
		return nil, errors.New("policyVersion is empty")
	}

	a := &Authorizer{enforcer: enforcer, policyVersion: policyVersion}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// AuthorizerOption configures an Authorizer.
type AuthorizerOption func(*Authorizer)

// WithDecisionCache enables a bounded LRU cache for authorization decisions.
// size <= 0 disables the cache.
func WithDecisionCache(size int) AuthorizerOption {
	return func(a *Authorizer) {
		if size <= 0 {
			a.cache = nil
			return
		}
		c, err := lru.New[cacheKey, cacheEntry](size)
		if err != nil {
			// lru.New only errors on non-positive size; treat any error as disabled.
			a.cache = nil
			return
		}
		a.cache = c
	}
}

// WithDecisionCacheFromEnv enables cache when TOKENS_MITH_AUTHZ_CACHE_SIZE is a
// positive integer.
func WithDecisionCacheFromEnv() AuthorizerOption {
	return func(a *Authorizer) {
		s := strings.TrimSpace(os.Getenv(EnvAuthzCacheSize))
		if s == "" {
			return
		}
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return
		}
		WithDecisionCache(n)(a)
	}
}

// Authorize evaluates whether principal may perform action on object.
//
// Services should typically call this from HTTP middleware.
func (a *Authorizer) Authorize(ctx context.Context, principal Principal, object, action string) (Decision, *AuthzResult) {
	_ = ctx

	pv := a.policyVersion

	res := &AuthzResult{PolicyVersion: pv}

	pid := strings.TrimSpace(principal.ID)
	if pid == "" {
		res.Reason = "principal missing id"
		return DecisionIndeterminate, res
	}
	if strings.TrimSpace(object) == "" || strings.TrimSpace(action) == "" {
		res.Reason = "missing object or action"
		return DecisionIndeterminate, res
	}

	roles := normalizeRoles(principal.Roles)
	if len(roles) == 0 {
		res.Reason = "principal has no roles"
		return DecisionIndeterminate, res
	}
	res.MatchedRoles = nil

	key := cacheKey{
		PrincipalID: pid,
		RolesHash:   hashStrings(roles),
		Object:      object,
		Action:      action,
		PolicyVer:   pv,
	}

	if ce, ok := a.cacheGet(key); ok {
		res.Cached = true
		res.MatchedRoles = append([]string(nil), ce.MatchedRoles...)
		res.Reason = ce.Reason
		return ce.Decision, res
	}

	matched, decision, reason := a.evaluateRoles(roles, object, action)
	res.MatchedRoles = matched
	res.Reason = reason

	a.cacheAdd(key, cacheEntry{Decision: decision, MatchedRoles: matched, Reason: reason})
	return decision, res
}

func (a *Authorizer) evaluateRoles(roles []string, object, action string) ([]string, Decision, string) {
	var matched []string
	for _, r := range roles {
		sub := "role:" + r
		ok, err := a.enforcer.Enforce(sub, object, action)
		if err != nil {
			return nil, DecisionError, fmt.Sprintf("casbin enforce error: %v", err)
		}
		if ok {
			matched = append(matched, r)
		}
	}
	if len(matched) > 0 {
		return matched, DecisionAllow, "allowed"
	}
	return nil, DecisionDeny, "denied by policy"
}

type cacheKey struct {
	PrincipalID string
	RolesHash   string
	Object      string
	Action      string
	PolicyVer   string
}

type cacheEntry struct {
	Decision     Decision
	MatchedRoles []string
	Reason       string
}

func (a *Authorizer) cacheGet(k cacheKey) (cacheEntry, bool) {
	a.cacheMu.RLock()
	c := a.cache
	a.cacheMu.RUnlock()
	if c == nil {
		return cacheEntry{}, false
	}
	v, ok := c.Get(k)
	return v, ok
}

func (a *Authorizer) cacheAdd(k cacheKey, v cacheEntry) {
	a.cacheMu.RLock()
	c := a.cache
	a.cacheMu.RUnlock()
	if c == nil {
		return
	}
	c.Add(k, v)
}

func normalizeRoles(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, r := range in {
		r = strings.TrimSpace(r)
		r = strings.TrimPrefix(r, "role:")
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

func hashStrings(ss []string) string {
	h := sha256.New()
	for _, s := range ss {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
