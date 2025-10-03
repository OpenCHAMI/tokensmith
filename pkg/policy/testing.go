// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policy provides testing utilities for policy engines
package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// PolicyTestSuite provides a comprehensive testing framework for policy engines
type PolicyTestSuite struct {
	Engine Engine
	Name   string
}

// NewPolicyTestSuite creates a new policy test suite
func NewPolicyTestSuite(engine Engine, name string) *PolicyTestSuite {
	return &PolicyTestSuite{
		Engine: engine,
		Name:   name,
	}
}

// TestCase represents a single policy test case
type TestCase struct {
	Name        string
	Context     *PolicyContext
	Expected    *PolicyDecision
	ExpectError bool
	Description string
}

// PolicyTestResult represents the result of a policy test
type PolicyTestResult struct {
	TestCase TestCase
	Actual   *PolicyDecision
	Error    error
	Duration time.Duration
	Passed   bool
	Message  string
}

// RunTestCase runs a single test case and returns the result
func (pts *PolicyTestSuite) RunTestCase(ctx context.Context, testCase TestCase) *PolicyTestResult {
	start := time.Now()
	actual, err := pts.Engine.EvaluatePolicy(ctx, testCase.Context)
	duration := time.Since(start)

	result := &PolicyTestResult{
		TestCase: testCase,
		Actual:   actual,
		Error:    err,
		Duration: duration,
	}

	// Check if error expectation matches
	if testCase.ExpectError {
		if err == nil {
			result.Passed = false
			result.Message = "Expected error but got none"
			return result
		}
		result.Passed = true
		result.Message = "Error occurred as expected"
		return result
	}

	// Check for unexpected error
	if err != nil {
		result.Passed = false
		result.Message = fmt.Sprintf("Unexpected error: %v", err)
		return result
	}

	// Compare with expected result
	if testCase.Expected == nil {
		result.Passed = actual != nil
		if !result.Passed {
			result.Message = "Expected non-nil decision but got nil"
		} else {
			result.Passed = true
			result.Message = "Got non-nil decision as expected"
		}
		return result
	}

	// Compare policy decisions
	if !comparePolicyDecisions(actual, testCase.Expected) {
		result.Passed = false
		result.Message = fmt.Sprintf("Policy decision mismatch. Expected: %+v, Got: %+v", testCase.Expected, actual)
		return result
	}

	result.Passed = true
	result.Message = "Test passed"
	return result
}

// RunTestSuite runs all test cases and returns results
func (pts *PolicyTestSuite) RunTestSuite(ctx context.Context, testCases []TestCase) []*PolicyTestResult {
	results := make([]*PolicyTestResult, len(testCases))

	for i, testCase := range testCases {
		results[i] = pts.RunTestCase(ctx, testCase)
	}

	return results
}

// RunTestSuiteWithT runs test cases using Go's testing framework
func (pts *PolicyTestSuite) RunTestSuiteWithT(t *testing.T, testCases []TestCase) {
	ctx := context.Background()
	results := pts.RunTestSuite(ctx, testCases)

	for _, result := range results {
		t.Run(result.TestCase.Name, func(t *testing.T) {
			if !result.Passed {
				t.Errorf("Test failed: %s", result.Message)
				if result.Error != nil {
					t.Errorf("Error: %v", result.Error)
				}
			}
		})
	}
}

// comparePolicyDecisions compares two policy decisions for equality
func comparePolicyDecisions(actual, expected *PolicyDecision) bool {
	if actual == nil && expected == nil {
		return true
	}
	if actual == nil || expected == nil {
		return false
	}

	// Compare scopes
	if !equalStringSlices(actual.Scopes, expected.Scopes) {
		return false
	}

	// Compare audiences
	if !equalStringSlices(actual.Audiences, expected.Audiences) {
		return false
	}

	// Compare permissions
	if !equalStringSlices(actual.Permissions, expected.Permissions) {
		return false
	}

	// Compare token lifetime (allow for small differences due to timing)
	if actual.TokenLifetime == nil && expected.TokenLifetime == nil {
		// Both nil, continue
	} else if actual.TokenLifetime == nil || expected.TokenLifetime == nil {
		return false
	} else {
		// Allow for small differences in token lifetime (within 1 second)
		diff := *actual.TokenLifetime - *expected.TokenLifetime
		if diff < 0 {
			diff = -diff
		}
		if diff > time.Second {
			return false
		}
	}

	// Compare additional claims
	if len(actual.AdditionalClaims) != len(expected.AdditionalClaims) {
		return false
	}
	for k, v := range expected.AdditionalClaims {
		if actual.AdditionalClaims[k] != v {
			return false
		}
	}

	return true
}

// equalStringSlices compares two string slices for equality (order-independent)
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	// Create maps for comparison
	mapA := make(map[string]int)
	mapB := make(map[string]int)

	for _, s := range a {
		mapA[s]++
	}
	for _, s := range b {
		mapB[s]++
	}

	for k, v := range mapA {
		if mapB[k] != v {
			return false
		}
	}

	return true
}

// TestDataFactory provides utilities for creating test data
type TestDataFactory struct{}

// NewTestDataFactory creates a new test data factory
func NewTestDataFactory() *TestDataFactory {
	return &TestDataFactory{}
}

// CreatePolicyContext creates a policy context for testing
func (tdf *TestDataFactory) CreatePolicyContext(username string, groups []string, claims map[string]interface{}) *PolicyContext {
	return &PolicyContext{
		Username:    username,
		Groups:      groups,
		Claims:      claims,
		ClusterID:   "test-cluster",
		OpenCHAMIID: "test-openchami",
	}
}

// CreatePolicyDecision creates a policy decision for testing
func (tdf *TestDataFactory) CreatePolicyDecision(scopes, audiences, permissions []string) *PolicyDecision {
	return &PolicyDecision{
		Scopes:      scopes,
		Audiences:   audiences,
		Permissions: permissions,
	}
}

// CreatePolicyDecisionWithLifetime creates a policy decision with token lifetime
func (tdf *TestDataFactory) CreatePolicyDecisionWithLifetime(scopes, audiences, permissions []string, lifetime time.Duration) *PolicyDecision {
	return &PolicyDecision{
		Scopes:        scopes,
		Audiences:     audiences,
		Permissions:   permissions,
		TokenLifetime: &lifetime,
	}
}

// CreatePolicyDecisionWithClaims creates a policy decision with additional claims
func (tdf *TestDataFactory) CreatePolicyDecisionWithClaims(scopes, audiences, permissions []string, additionalClaims map[string]interface{}) *PolicyDecision {
	return &PolicyDecision{
		Scopes:           scopes,
		Audiences:        audiences,
		Permissions:      permissions,
		AdditionalClaims: additionalClaims,
	}
}

// CreateTestCase creates a test case
func (tdf *TestDataFactory) CreateTestCase(name, description string, context *PolicyContext, expected *PolicyDecision, expectError bool) TestCase {
	return TestCase{
		Name:        name,
		Context:     context,
		Expected:    expected,
		ExpectError: expectError,
		Description: description,
	}
}

// BenchmarkPolicyEngine benchmarks a policy engine
func BenchmarkPolicyEngine(b *testing.B, engine Engine, policyCtx *PolicyContext) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluatePolicy(ctx, policyCtx)
		if err != nil {
			b.Fatalf("Policy evaluation failed: %v", err)
		}
	}
}

// BenchmarkPolicyEngineConcurrent benchmarks a policy engine with concurrent access
func BenchmarkPolicyEngineConcurrent(b *testing.B, engine Engine, policyCtx *PolicyContext) {
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := engine.EvaluatePolicy(ctx, policyCtx)
			if err != nil {
				b.Fatalf("Policy evaluation failed: %v", err)
			}
		}
	})
}
