// SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
//
// SPDX-License-Identifier: MIT

package main

import (
	"net/http"

	"github.com/openchami/tokensmith/pkg/authz"
)

// routeMapper is an explicit RouteMapper example.
//
// It maps a stable HTTP route to a stable (object, action) taxonomy.
// This style is a good fit for Fabrica-generated CRUD handlers.
//
// Note: public bypass is owned by the middleware; this mapper only maps.
type routeMapper struct{}

func (routeMapper) Map(r *http.Request, _ authz.Principal) (authz.RouteDecision, error) {
	if r == nil {
		return authz.RouteDecision{Mapped: false}, nil
	}
	if r.URL != nil && r.URL.Path == "/protected/mapper" {
		return authz.RouteDecision{Mapped: true, Object: "minisvc:mapper", Action: "read"}, nil
	}
	return authz.RouteDecision{Mapped: false}, nil
}
