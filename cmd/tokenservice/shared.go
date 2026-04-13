// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import "strings"

// ParseScopeCSV parses comma- or whitespace-separated scopes and drops empty entries.
func ParseScopeCSV(scopesCSV string) []string {
	if strings.TrimSpace(scopesCSV) == "" {
		return nil
	}

	raw := strings.FieldsFunc(scopesCSV, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(raw))
	for _, scope := range raw {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		out = append(out, scope)
	}
	return out
}
