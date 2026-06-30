// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authn

import (
	"strings"
)

// Standard ACR values per NIST SP 800-63-3 and OpenID Connect Core
// See: https://openid.net/specs/openid-connect-core-1_0.html#acrSemantics
const (
	ACR_AAL1        = "urn:nist:aal:1"
	ACR_AAL2        = "urn:nist:aal:2"
	ACR_AAL3        = "urn:nist:aal:3"
	ACR_MFARequired = "urn:mfa:required"
	ACR_FIDO2       = "urn:fido:u2f"
)

var acrHierarchy = map[string]int{
	"":              0,
	ACR_AAL1:        1,
	ACR_MFARequired: 2,
	ACR_AAL2:        2,
	ACR_FIDO2:       3,
	ACR_AAL3:        3,
}

func MeetsACRRequirement(currentACR string, requestedACRs []string) bool {
	if len(requestedACRs) == 0 {
		return true
	}

	currentLevel := getACRLevel(currentACR)

	for _, requestedACR := range requestedACRs {
		requestedLevel := getACRLevel(requestedACR)
		if currentLevel >= requestedLevel {
			return true
		}
	}

	return false
}

func getACRLevel(acr string) int {
	acr = strings.TrimSpace(acr)

	if level, ok := acrHierarchy[acr]; ok {
		return level
	}

	if strings.Contains(acr, "aal:3") || strings.Contains(acr, "fido") || strings.Contains(acr, "webauthn") {
		return 3
	}

	if strings.Contains(acr, "aal:2") || strings.Contains(acr, "mfa") || strings.Contains(acr, "2fa") {
		return 2
	}

	if strings.Contains(acr, "aal:1") {
		return 1
	}

	return 0
}

func GetHighestACR(acrs []string) string {
	if len(acrs) == 0 {
		return ""
	}

	highestACR := acrs[0]
	highestLevel := getACRLevel(highestACR)

	for _, acr := range acrs[1:] {
		level := getACRLevel(acr)
		if level > highestLevel {
			highestLevel = level
			highestACR = acr
		}
	}

	return highestACR
}
