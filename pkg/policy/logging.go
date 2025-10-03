// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

// Package policy provides logging utilities for policy decisions
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// PolicyLogger provides structured logging for policy decisions
type PolicyLogger struct {
	logger zerolog.Logger
}

// NewPolicyLogger creates a new policy logger
func NewPolicyLogger() *PolicyLogger {
	return &PolicyLogger{
		logger: log.With().Str("component", "policy").Logger(),
	}
}

// LogPolicyDecision logs a policy decision with full context
func (pl *PolicyLogger) LogPolicyDecision(ctx context.Context, policyCtx *PolicyContext, decision *PolicyDecision, engineName string, duration time.Duration, err error) {
	event := pl.logger.Info()

	if err != nil {
		event = pl.logger.Error().Err(err)
	}

	event.
		Str("engine", engineName).
		Str("username", policyCtx.Username).
		Strs("groups", policyCtx.Groups).
		Str("cluster_id", policyCtx.ClusterID).
		Str("openchami_id", policyCtx.OpenCHAMIID).
		Dur("evaluation_duration", duration).
		Interface("claims", policyCtx.Claims)

	if decision != nil {
		event.
			Strs("scopes", decision.Scopes).
			Strs("audiences", decision.Audiences).
			Strs("permissions", decision.Permissions).
			Interface("additional_claims", decision.AdditionalClaims)

		if decision.TokenLifetime != nil {
			event.Dur("token_lifetime", *decision.TokenLifetime)
		}
	}

	event.Msg("policy decision evaluated")
}

// LogPolicyError logs policy evaluation errors with context
func (pl *PolicyLogger) LogPolicyError(ctx context.Context, policyCtx *PolicyContext, engineName string, err error) {
	pl.logger.Error().
		Err(err).
		Str("engine", engineName).
		Str("username", policyCtx.Username).
		Strs("groups", policyCtx.Groups).
		Str("cluster_id", policyCtx.ClusterID).
		Str("openchami_id", policyCtx.OpenCHAMIID).
		Interface("claims", policyCtx.Claims).
		Msg("policy evaluation failed")
}

// LogPolicyConfigChange logs when policy configuration changes
func (pl *PolicyLogger) LogPolicyConfigChange(engineName, configPath string, err error) {
	event := pl.logger.Info()
	if err != nil {
		event = pl.logger.Error().Err(err)
	}

	event.
		Str("engine", engineName).
		Str("config_path", configPath).
		Msg("policy configuration changed")
}

// LogPolicyValidation logs policy configuration validation results
func (pl *PolicyLogger) LogPolicyValidation(engineName string, isValid bool, err error) {
	event := pl.logger.Info()
	if err != nil {
		event = pl.logger.Error().Err(err)
	}

	event.
		Str("engine", engineName).
		Bool("valid", isValid).
		Msg("policy configuration validated")
}

// PolicyDecisionSummary provides a summary of policy decisions for debugging
type PolicyDecisionSummary struct {
	Engine         string                 `json:"engine"`
	Username       string                 `json:"username"`
	Groups         []string               `json:"groups"`
	Scopes         []string               `json:"scopes"`
	Audiences      []string               `json:"audiences"`
	Permissions    []string               `json:"permissions"`
	Duration       time.Duration          `json:"duration_ms"`
	Timestamp      time.Time              `json:"timestamp"`
	Error          string                 `json:"error,omitempty"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// GetPolicyDecisionSummary creates a summary of a policy decision for debugging
func GetPolicyDecisionSummary(engineName string, policyCtx *PolicyContext, decision *PolicyDecision, duration time.Duration, err error) *PolicyDecisionSummary {
	summary := &PolicyDecisionSummary{
		Engine:         engineName,
		Username:       policyCtx.Username,
		Groups:         policyCtx.Groups,
		Duration:       duration,
		Timestamp:      time.Now(),
		AdditionalData: make(map[string]interface{}),
	}

	if err != nil {
		summary.Error = err.Error()
	}

	if decision != nil {
		summary.Scopes = decision.Scopes
		summary.Audiences = decision.Audiences
		summary.Permissions = decision.Permissions
	}

	// Add cluster and OpenCHAMI information
	summary.AdditionalData["cluster_id"] = policyCtx.ClusterID
	summary.AdditionalData["openchami_id"] = policyCtx.OpenCHAMIID

	return summary
}

// ToJSON converts a policy decision summary to JSON
func (pds *PolicyDecisionSummary) ToJSON() ([]byte, error) {
	return json.MarshalIndent(pds, "", "  ")
}

// String returns a string representation of the policy decision summary
func (pds *PolicyDecisionSummary) String() string {
	json, err := pds.ToJSON()
	if err != nil {
		return fmt.Sprintf("PolicyDecisionSummary{Engine: %s, Username: %s, Error: %v}",
			pds.Engine, pds.Username, err)
	}
	return string(json)
}
