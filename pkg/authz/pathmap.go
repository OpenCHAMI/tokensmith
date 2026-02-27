// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package authz

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// MethodToAction maps an HTTP method to a Casbin action string.
type MethodToAction func(method string) string

// MethodToActionLiteral returns action = method (as received).
func MethodToActionLiteral() MethodToAction {
	return func(method string) string { return method }
}

// MethodToActionREST returns a REST-ish action mapping:
//   - GET/HEAD -> read
//   - POST/PUT/PATCH -> write
//   - DELETE -> delete
//   - other -> method literal
func MethodToActionREST() MethodToAction {
	return func(method string) string {
		switch strings.ToUpper(method) {
		case http.MethodGet, http.MethodHead:
			return "read"
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			return "write"
		case http.MethodDelete:
			return "delete"
		default:
			return method
		}
	}
}

// NormalizeEscapedPath implements the TokenSmith path normalization rules for
// path/method style authorization.
//
// Spec: docs/authz-spec.md §3.
//
// Behavior summary:
//   - Uses u.EscapedPath() if non-empty, else returns "/".
//   - Rejects malformed %-escapes with BadRequestError.
//   - Preserves encoded slashes (%2F) by only unescaping *non-slash* sequences.
//     (i.e., %2F remains %2F, preventing path segment ambiguity).
//   - Cleans dot segments via path.Clean while keeping a leading slash.
//
// The returned string is safe to feed to Casbin keyMatch/keyMatch2 matchers.
func NormalizeEscapedPath(u *url.URL) (string, error) {
	if u == nil {
		return "/", nil
	}
	ep := ""
	if u.RawPath != "" {
		ep = u.RawPath
	} else {
		ep = u.EscapedPath()
	}
	if ep == "" {
		ep = "/"
	}

	nonSlashUnescaped, err := unescapeExceptSlash(ep)
	if err != nil {
		return "", NewBadRequestError("malformed URL path")
	}

	// Ensure absolute and cleaned. path.Clean preserves %2F sequences as literal
	// text because they are not actual slashes.
	clean := path.Clean("/" + strings.TrimPrefix(nonSlashUnescaped, "/"))
	if clean == "." {
		clean = "/"
	}
	return clean, nil
}

// PathMethodMapper is a RouteMapper implementation that feeds Casbin with:
//   - object = normalized URL path
//   - action = normalized method (literal or REST-ish)
//   - domain = optional extractor
//
// Public bypass is NOT handled here; middleware remains the single owner.
type PathMethodMapper struct {
	MethodToAction MethodToAction
	DomainFunc     func(r *http.Request, p Principal) (string, error)
}

func (m PathMethodMapper) Map(r *http.Request, p Principal) (RouteDecision, error) {
	if r == nil {
		return RouteDecision{Mapped: false}, nil
	}

	obj, err := NormalizeEscapedPath(r.URL)
	if err != nil {
		return RouteDecision{}, err
	}

	m2a := m.MethodToAction
	if m2a == nil {
		m2a = MethodToActionLiteral()
	}
	act := m2a(r.Method)

	dom := ""
	if m.DomainFunc != nil {
		dom, err = m.DomainFunc(r, p)
		if err != nil {
			return RouteDecision{}, err
		}
	}

	return RouteDecision{Mapped: true, Object: obj, Action: act, Domain: dom}, nil
}

func unescapeExceptSlash(s string) (string, error) {
	// Validate percent-escapes and unescape all except %2F/%2f.
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", url.EscapeError(s[i:])
		}
		hex := s[i+1 : i+3]
		if strings.EqualFold(hex, "2f") {
			// Preserve encoded slash.
			b.WriteByte('%')
			b.WriteString(hex)
			i += 2
			continue
		}
		// Unescape this sequence.
		ch, err := url.PathUnescape("%" + hex)
		if err != nil || len(ch) != 1 {
			if err == nil {
				err = url.EscapeError("%" + hex)
			}
			return "", err
		}
		b.WriteByte(ch[0])
		i += 2
	}
	return b.String(), nil
}
