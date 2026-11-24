// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
// SPDX-License-Identifier: MIT

package token

import (
	"errors"
	"net/url"
)

var ErrHumanSessionDenied = errors.New("human session denied")

// HumanSessionPolicy contains only consumer trust and lifetime limits, no secrets.
type HumanSessionPolicy struct {
	ClusterIssuer   string
	Audience        string
	GitLabIssuer    string
	ProjectID       int64
	CacheSeconds    int64
	TokenSeconds    int64
	SkewSeconds     int64
	AbsoluteSeconds int64
}

func (p HumanSessionPolicy) Validate() error {
	u, err := url.Parse(p.GitLabIssuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" {
		return ErrHumanSessionDenied
	}
	if p.ProjectID <= 0 || p.ClusterIssuer == "" || p.Audience == "" || p.CacheSeconds <= 0 || p.CacheSeconds > 90 || p.TokenSeconds <= 0 || p.TokenSeconds > 180 || p.SkewSeconds < 0 || p.SkewSeconds > 30 || p.AbsoluteSeconds != 36000 || p.CacheSeconds+p.TokenSeconds+p.SkewSeconds > 300 {
		return ErrHumanSessionDenied
	}
	return nil
}
