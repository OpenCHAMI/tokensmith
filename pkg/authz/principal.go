// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

// Principal is the normalized caller identity used for authorization.
//
// Services are responsible for mapping authenticated identity (e.g. JWT/OIDC
// claims) into this structure.
//
// Roles are expected WITHOUT the "role:" prefix (e.g. "admin", "viewer").
// The Authorizer will apply the required Casbin subject prefix.
type Principal struct {
	// ID is the stable identifier for the principal (user id, client id, etc.).
	ID string

	// Roles is the set of RBAC roles assigned to the principal.
	Roles []string
}
