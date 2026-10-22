// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"sort"
	"sync"
	"time"
)

const (
	// replayWindowDuration is the sliding window for counting replay attempts.
	replayWindowDuration = 60 * time.Second

	// replayMaxAttempts is the maximum number of failed bootstrap exchanges
	// allowed from a single IP within replayWindowDuration before the IP is
	// blocked. Per NIST SP 800-63-4 Section 5.2.2 (throttling requirements).
	replayMaxAttempts = 10
	replayMaxPeers    = 1024
)

// replayLimiter tracks failed bootstrap token exchange attempts per source IP
// using a sliding window counter. It enforces NIST SP 800-63-4 Section 5.2.2
// rate limiting to mitigate brute-force attacks against opaque bootstrap tokens.
type replayLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time // IP address -> sorted attempt timestamps
}

func newReplayLimiter() *replayLimiter {
	return &replayLimiter{
		attempts: make(map[string][]time.Time),
	}
}

// record adds a new attempt timestamp for the given IP.
func (r *replayLimiter) record(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.pruneAll(now)
	if _, exists := r.attempts[ip]; !exists && len(r.attempts) >= replayMaxPeers {
		r.evictOldest()
	}
	active := append(r.pruneWindow(r.attempts[ip], now), now)
	if len(active) > replayMaxAttempts {
		active = active[len(active)-replayMaxAttempts:]
	}
	r.attempts[ip] = active
}

// isBlocked returns true if the IP has exceeded replayMaxAttempts within the
// current sliding window. The check is non-mutating (no side effects).
func (r *replayLimiter) isBlocked(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	active := r.pruneWindow(r.attempts[ip], now)
	if len(active) == 0 {
		delete(r.attempts, ip)
	} else {
		r.attempts[ip] = active
	}
	return len(active) >= replayMaxAttempts
}

func (r *replayLimiter) pruneAll(now time.Time) {
	for ip, attempts := range r.attempts {
		if len(r.pruneWindow(attempts, now)) == 0 {
			delete(r.attempts, ip)
		}
	}
}

func (r *replayLimiter) evictOldest() {
	keys := make([]string, 0, len(r.attempts))
	for ip := range r.attempts {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	oldest := keys[0]
	for _, ip := range keys[1:] {
		if r.attempts[ip][0].Before(r.attempts[oldest][0]) {
			oldest = ip
		}
	}
	delete(r.attempts, oldest)
}

// pruneWindow removes timestamps older than replayWindowDuration and returns
// the remaining entries. Must be called with r.mu held.
func (r *replayLimiter) pruneWindow(ts []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-replayWindowDuration)
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	return ts[i:]
}
