// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import "time"

func testServiceIdentityPolicy(now time.Time) *ServiceIdentityPolicy {
	return &ServiceIdentityPolicy{
		Version: ServiceIdentityPolicyVersion, ID: "service-policy-1", Subject: "boot-service", Audience: "metadata-service", Scopes: []string{"read"}, RefreshTTL: 30 * time.Minute, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}
