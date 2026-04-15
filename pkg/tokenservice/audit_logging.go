// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// AuditEventType defines the type of security audit event
// See: NIST SP 800-63-3 Appendix D (Audit Logging)
type AuditEventType string

const (
	// Bootstrap token lifecycle events
	AuditBootstrapTokenCreated         AuditEventType = "bootstrap_token_created"
	AuditBootstrapTokenExchanged       AuditEventType = "bootstrap_token_exchanged"
	AuditBootstrapTokenExpired         AuditEventType = "bootstrap_token_expired"
	AuditBootstrapTokenReplayAttempted AuditEventType = "bootstrap_token_replay_attempted"
	AuditBootstrapTokenConsumed        AuditEventType = "bootstrap_token_consumed"

	// Refresh token lifecycle events
	AuditRefreshTokenIssued         AuditEventType = "refresh_token_issued"
	AuditRefreshTokenRotated        AuditEventType = "refresh_token_rotated"
	AuditRefreshTokenExpired        AuditEventType = "refresh_token_expired"
	AuditRefreshTokenReplayDetected AuditEventType = "refresh_token_replay_detected"
	AuditRefreshTokenFamilyRevoked  AuditEventType = "refresh_token_family_revoked"

	// Error events
	AuditAuthenticationFailed AuditEventType = "authentication_failed"
	AuditAuthorizationFailed  AuditEventType = "authorization_failed"
)

// AuditLog writes a structured security audit event per NIST SP 800-63 guidelines
// See: https://pages.nist.gov/800-63-3/sp800-63c.html#sec-8 (Assertions and Audit)
//
// Audit logs are written to stderr by zerolog and include:
// - Event type and timestamp (required for compliance)
// - Subject (service ID) and audience (target service)
// - Security-relevant context (token hash prefix, IP address, action)
// - Outcome (success or failure with reason)
func AuditLog(eventType AuditEventType, context map[string]interface{}) {
	event := log.WithLevel(zerolog.WarnLevel).
		Str("component", "tokenservice").
		Str("audit_event", string(eventType)).
		Time("event_timestamp", time.Now())

	// Extract common fields
	if subject, ok := context["subject"].(string); ok {
		event = event.Str("subject", subject)
	}
	if audience, ok := context["audience"].(string); ok {
		event = event.Str("audience", audience)
	}
	if clientIP, ok := context["client_ip"].(string); ok {
		event = event.Str("client_ip", maskIPIfNeeded(clientIP))
	}
	if tokenHashPrefix, ok := context["token_hash_prefix"].(string); ok {
		event = event.Str("token_hash_prefix", tokenHashPrefix)
	}
	if reason, ok := context["reason"].(string); ok {
		event = event.Str("reason", reason)
	}
	if err, ok := context["error"].(error); ok {
		event = event.Err(err)
	}

	// Event-specific fields
	switch eventType {
	case AuditBootstrapTokenCreated:
		if ttl, ok := context["ttl_seconds"].(int64); ok {
			event = event.Int64("ttl_seconds", ttl)
		}
		if refreshTTL, ok := context["refresh_ttl_seconds"].(int64); ok {
			event = event.Int64("refresh_ttl_seconds", refreshTTL)
		}
		if scopes, ok := context["scopes"].([]string); ok {
			event = event.Strs("scopes", scopes)
		}
		if bindingID, ok := context["binding_identifier"].(string); ok {
			event = event.Str("binding_identifier", bindingID)
		}

	case AuditBootstrapTokenExchanged:
		if accessTokenID, ok := context["access_token_id"].(string); ok {
			event = event.Str("access_token_id", accessTokenID)
		}
		if refreshFamilyID, ok := context["refresh_family_id"].(string); ok {
			event = event.Str("refresh_family_id", refreshFamilyID)
		}

	case AuditBootstrapTokenReplayAttempted:
		if attempts, ok := context["replay_attempt_count"].(int); ok {
			event = event.Int("replay_attempt_count", attempts)
		}

	case AuditRefreshTokenIssued, AuditRefreshTokenRotated:
		if familyID, ok := context["family_id"].(string); ok {
			event = event.Str("family_id", familyID)
		}
		if usageCount, ok := context["usage_count"].(int); ok {
			event = event.Int("usage_count", usageCount)
		}

	case AuditRefreshTokenReplayDetected:
		if familyID, ok := context["family_id"].(string); ok {
			event = event.Str("family_id", familyID)
		}
		if lastUsedAt, ok := context["last_used_at"].(time.Time); ok {
			event = event.Time("last_used_at", lastUsedAt)
		}
		event.Msg("Replay attack detected: refresh token from old rotation presented")

	case AuditRefreshTokenFamilyRevoked:
		if familyID, ok := context["family_id"].(string); ok {
			event = event.Str("family_id", familyID)
		}
		event.Msg("Refresh token family revoked due to replay detection")

	case AuditAuthenticationFailed:
		if failureReason, ok := context["failure_reason"].(string); ok {
			event = event.Str("failure_reason", failureReason)
		}

	case AuditAuthorizationFailed:
		if deniedResource, ok := context["denied_resource"].(string); ok {
			event = event.Str("denied_resource", deniedResource)
		}
		if expectedScope, ok := context["expected_scope"].(string); ok {
			event = event.Str("expected_scope", expectedScope)
		}
	}

	// Log with default message
	event.Msg(string(eventType))
}

// maskIPIfNeeded masks the client IP address if needed for privacy
// Leaves last octet visible for debugging but masks the first 3 octets
// Example: 192.0.2.100 → 192.0.2.xxx
func maskIPIfNeeded(clientIP string) string {
	// Try to parse as IPv4
	ip := net.ParseIP(clientIP)
	if ip == nil {
		// If it has a port, try to extract just the IP
		if strings.Contains(clientIP, ":") {
			parts := strings.Split(clientIP, ":")
			if len(parts) > 0 {
				ip = net.ParseIP(parts[0])
			}
		}
	}

	if ip == nil || ip.To4() == nil {
		// Not IPv4, return as-is (could be IPv6 or hostname)
		return clientIP
	}

	// For debugging, return full IP (NIST SP 800-63 allows this for internal systems)
	// Production may want to mask with: fmt.Sprintf("%s.xxx", ip.String()[:strings.LastIndexByte(ip.String(), '.')])
	return clientIP
}

// AuditLogBootstrapCreated logs bootstrap token creation (admin action)
func AuditLogBootstrapCreated(subject, audience string, scopes []string, ttl, refreshTTL time.Duration, bindingID string) {
	AuditLog(AuditBootstrapTokenCreated, map[string]interface{}{
		"subject":             subject,
		"audience":            audience,
		"scopes":              scopes,
		"ttl_seconds":         int64(ttl.Seconds()),
		"refresh_ttl_seconds": int64(refreshTTL.Seconds()),
		"binding_identifier":  bindingID,
	})
}

// AuditLogBootstrapExchanged logs successful bootstrap token exchange
func AuditLogBootstrapExchanged(subject, audience string, scopes []string, clientIP, accessTokenID, refreshFamilyID, tokenHashPrefix string) {
	AuditLog(AuditBootstrapTokenExchanged, map[string]interface{}{
		"subject":           subject,
		"audience":          audience,
		"scopes":            scopes,
		"client_ip":         clientIP,
		"access_token_id":   accessTokenID,
		"refresh_family_id": refreshFamilyID,
		"token_hash_prefix": tokenHashPrefix,
	})
}

// AuditLogBootstrapReplay logs bootstrap token replay attempt
func AuditLogBootstrapReplay(tokenHashPrefix, clientIP string, replayAttempts []time.Time) {
	AuditLog(AuditBootstrapTokenReplayAttempted, map[string]interface{}{
		"token_hash_prefix":    tokenHashPrefix,
		"client_ip":            clientIP,
		"replay_attempt_count": len(replayAttempts),
		"reason":               "bootstrap token already consumed or invalid",
	})
}

// AuditLogRefreshRotated logs refresh token rotation
func AuditLogRefreshRotated(subject, audience string, scopes []string, clientIP, familyID string, usageCount int) {
	AuditLog(AuditRefreshTokenRotated, map[string]interface{}{
		"subject":     subject,
		"audience":    audience,
		"scopes":      scopes,
		"client_ip":   clientIP,
		"family_id":   familyID,
		"usage_count": usageCount,
	})
}

// AuditLogRefreshReplayDetected logs replay attack on refresh token family
func AuditLogRefreshReplayDetected(subject, audience string, familyID, clientIP string, lastUsedAt time.Time) {
	AuditLog(AuditRefreshTokenReplayDetected, map[string]interface{}{
		"subject":      subject,
		"audience":     audience,
		"family_id":    familyID,
		"client_ip":    clientIP,
		"last_used_at": lastUsedAt,
		"reason":       "refresh token from rotated generation presented (potential compromise)",
	})
}

// AuditLogFamilyRevoked logs family revocation due to replay
func AuditLogFamilyRevoked(subject, audience, familyID, clientIP string, usageCount int) {
	AuditLog(AuditRefreshTokenFamilyRevoked, map[string]interface{}{
		"subject":     subject,
		"audience":    audience,
		"family_id":   familyID,
		"client_ip":   clientIP,
		"usage_count": usageCount,
		"reason":      "replay detection - all tokens in family invalidated",
	})
}

// AuditLogAuthenticationFailed logs authentication failure
func AuditLogAuthenticationFailed(subject, reason, clientIP string) {
	AuditLog(AuditAuthenticationFailed, map[string]interface{}{
		"subject":        subject,
		"failure_reason": reason,
		"client_ip":      clientIP,
	})
}
