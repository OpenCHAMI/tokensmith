// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"net"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

func requestClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if clientIP := middleware.GetClientIP(r.Context()); clientIP != "" {
		return clientIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
