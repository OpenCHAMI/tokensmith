// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMeetsACRRequirement_ExactMatch(t *testing.T) {
	assert.True(t, MeetsACRRequirement(ACR_AAL2, []string{ACR_AAL2}))
	assert.True(t, MeetsACRRequirement(ACR_MFARequired, []string{ACR_MFARequired}))
	assert.True(t, MeetsACRRequirement(ACR_AAL3, []string{ACR_AAL3}))
}

func TestMeetsACRRequirement_HigherMeetsLower(t *testing.T) {
	assert.True(t, MeetsACRRequirement(ACR_AAL2, []string{ACR_AAL1}))
	assert.True(t, MeetsACRRequirement(ACR_AAL3, []string{ACR_AAL2}))
	assert.True(t, MeetsACRRequirement(ACR_AAL3, []string{ACR_AAL1}))
	assert.True(t, MeetsACRRequirement(ACR_FIDO2, []string{ACR_AAL2}))
}

func TestMeetsACRRequirement_LowerDoesNotMeetHigher(t *testing.T) {
	assert.False(t, MeetsACRRequirement(ACR_AAL1, []string{ACR_AAL2}))
	assert.False(t, MeetsACRRequirement(ACR_AAL2, []string{ACR_AAL3}))
	assert.False(t, MeetsACRRequirement(ACR_AAL1, []string{ACR_MFARequired}))
	assert.False(t, MeetsACRRequirement("", []string{ACR_AAL1}))
}

func TestMeetsACRRequirement_MultipleRequested(t *testing.T) {
	assert.True(t, MeetsACRRequirement(ACR_AAL2, []string{ACR_AAL1, ACR_AAL2, ACR_AAL3}), "Should meet if ANY requested ACR is satisfied")
	assert.True(t, MeetsACRRequirement(ACR_AAL3, []string{ACR_AAL1, ACR_AAL2}), "Higher level satisfies any lower request")
	assert.False(t, MeetsACRRequirement(ACR_AAL1, []string{ACR_AAL2, ACR_AAL3}), "Lower level satisfies none of higher requests")
}

func TestMeetsACRRequirement_EmptyRequested(t *testing.T) {
	assert.True(t, MeetsACRRequirement(ACR_AAL1, []string{}))
	assert.True(t, MeetsACRRequirement("", []string{}))
	assert.True(t, MeetsACRRequirement(ACR_AAL3, nil))
}

func TestMeetsACRRequirement_EmptyCurrent(t *testing.T) {
	assert.False(t, MeetsACRRequirement("", []string{ACR_AAL1}))
	assert.False(t, MeetsACRRequirement("", []string{ACR_MFARequired}))
}

func TestMeetsACRRequirement_CustomACRStrings(t *testing.T) {
	assert.True(t, MeetsACRRequirement("urn:okta:loa:2fa:any", []string{ACR_AAL1}), "Custom MFA ACR should meet AAL1")
	assert.True(t, MeetsACRRequirement("urn:okta:loa:2fa:any", []string{ACR_MFARequired}), "Custom MFA ACR should meet urn:mfa:required")
	assert.True(t, MeetsACRRequirement("urn:custom:fido:strong", []string{ACR_AAL2}), "Custom FIDO ACR should meet AAL2")
	assert.True(t, MeetsACRRequirement("urn:custom:fido:strong", []string{ACR_AAL3}), "Custom FIDO ACR should meet AAL3")
}

func TestMeetsACRRequirement_EquivalentACRs(t *testing.T) {
	assert.True(t, MeetsACRRequirement(ACR_AAL2, []string{ACR_MFARequired}), "AAL2 and urn:mfa:required are equivalent")
	assert.True(t, MeetsACRRequirement(ACR_MFARequired, []string{ACR_AAL2}), "urn:mfa:required and AAL2 are equivalent")
	assert.True(t, MeetsACRRequirement(ACR_AAL3, []string{ACR_FIDO2}), "AAL3 and FIDO2 are equivalent level")
	assert.True(t, MeetsACRRequirement(ACR_FIDO2, []string{ACR_AAL3}), "FIDO2 and AAL3 are equivalent level")
}

func TestGetACRLevel_StandardValues(t *testing.T) {
	assert.Equal(t, 0, getACRLevel(""))
	assert.Equal(t, 1, getACRLevel(ACR_AAL1))
	assert.Equal(t, 2, getACRLevel(ACR_AAL2))
	assert.Equal(t, 2, getACRLevel(ACR_MFARequired))
	assert.Equal(t, 3, getACRLevel(ACR_AAL3))
	assert.Equal(t, 3, getACRLevel(ACR_FIDO2))
}

func TestGetACRLevel_CustomValues(t *testing.T) {
	assert.Equal(t, 1, getACRLevel("urn:custom:aal:1"))
	assert.Equal(t, 2, getACRLevel("urn:okta:loa:2fa:any"))
	assert.Equal(t, 2, getACRLevel("urn:custom:mfa:required"))
	assert.Equal(t, 3, getACRLevel("urn:custom:aal:3"))
	assert.Equal(t, 3, getACRLevel("urn:custom:fido:strong"))
	assert.Equal(t, 3, getACRLevel("urn:custom:webauthn"))
}

func TestGetACRLevel_UnknownValues(t *testing.T) {
	assert.Equal(t, 0, getACRLevel("urn:unknown:acr"))
	assert.Equal(t, 0, getACRLevel("random-string"))
}

func TestGetHighestACR_MultipleValues(t *testing.T) {
	result := GetHighestACR([]string{ACR_AAL1, ACR_AAL2, ACR_AAL3})
	assert.Equal(t, ACR_AAL3, result)

	result = GetHighestACR([]string{ACR_MFARequired, ACR_AAL1, ACR_FIDO2})
	assert.Equal(t, ACR_FIDO2, result)

	result = GetHighestACR([]string{ACR_AAL2, ACR_MFARequired})
	assert.Contains(t, []string{ACR_AAL2, ACR_MFARequired}, result, "Either AAL2 or MFARequired is valid (same level)")
}

func TestGetHighestACR_SingleValue(t *testing.T) {
	result := GetHighestACR([]string{ACR_AAL2})
	assert.Equal(t, ACR_AAL2, result)
}

func TestGetHighestACR_Empty(t *testing.T) {
	result := GetHighestACR([]string{})
	assert.Equal(t, "", result)

	result = GetHighestACR(nil)
	assert.Equal(t, "", result)
}

func TestGetHighestACR_CustomValues(t *testing.T) {
	result := GetHighestACR([]string{"urn:okta:loa:2fa:any", "urn:custom:fido:strong", ACR_AAL1})
	assert.Equal(t, "urn:custom:fido:strong", result, "FIDO (level 3) should be highest")
}

func TestACRHierarchy_Ordering(t *testing.T) {
	levels := []struct {
		acr   string
		level int
	}{
		{"", 0},
		{ACR_AAL1, 1},
		{ACR_AAL2, 2},
		{ACR_MFARequired, 2},
		{ACR_AAL3, 3},
		{ACR_FIDO2, 3},
	}

	for i := 0; i < len(levels); i++ {
		for j := i + 1; j < len(levels); j++ {
			lower := levels[i]
			higher := levels[j]

			if lower.level < higher.level {
				assert.True(t, MeetsACRRequirement(higher.acr, []string{lower.acr}),
					"%s (level %d) should meet requirement for %s (level %d)",
					higher.acr, higher.level, lower.acr, lower.level)

				assert.False(t, MeetsACRRequirement(lower.acr, []string{higher.acr}),
					"%s (level %d) should NOT meet requirement for %s (level %d)",
					lower.acr, lower.level, higher.acr, higher.level)
			}
		}
	}
}
