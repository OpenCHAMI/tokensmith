package deviceauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

func random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure random unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Provider is the verified identity source; callers never submit their own roles.
type Provider interface {
	Start(context.Context) (Device, error)
	Poll(context.Context, string) (Credential, error)
	Refresh(context.Context, string) (Credential, error)
	Verify(context.Context, string, time.Time) (Identity, error)
	Membership(context.Context, int64) (int, error)
	Revoke(context.Context, string) error
}

// Signer issues the cluster token only after the authority has checked identity.
type Signer interface {
	Sign(Claims) (string, error)
}

// Audit contains only verified immutable IDs and allowlisted outcomes. It never
// receives credentials, renewal handles, codes, usernames, server errors or JWTs.
type Audit struct {
	Event     string `json:"event"`
	Issuer    string `json:"gitlab_issuer"`
	ProjectID int64  `json:"project_id"`
	UserID    int64  `json:"user_id"`
	SessionID string `json:"session_id"`
	Role      string `json:"role"`
	At        int64  `json:"at"`
}

type session struct {
	gate                chan struct{} // Serializes renewal and logout for this session.
	credential          Credential
	userID              int64
	sessionID           string
	approvedAt          time.Time // First verified approval; never moved by renewal.
	sessionExpiresAt    time.Time // Absolute session cap, even after GitLab refresh.
	upstreamExpiresAt   time.Time // Current GitLab access-token expiry.
	membershipCheckedAt time.Time // Start of the last effective-membership lookup.
	lastIssuedAt        time.Time // Last successful issuance; rejects a backwards clock.
	role                string
}

type transaction struct {
	gate       chan struct{} // Serializes polling for this transaction.
	device     Device
	expiresAt  time.Time
	nextPollAt time.Time
}

// DeviceResponse hides the GitLab device secret behind a broker-owned handle.
type DeviceResponse struct {
	Transaction string `json:"transaction"`
	UserCode    string `json:"user_code"`
	URI         string `json:"verification_uri"`
	Expires     int64  `json:"expires_in"`
	Interval    int64  `json:"interval"`
}

// Result contains a short cluster token and, on login, a private renewal handle.
type Result struct {
	Access   string `json:"access_token,omitempty"`
	Renewal  string `json:"renewal_token,omitempty"`
	Type     string `json:"token_type,omitempty"`
	Expires  int64  `json:"expires_in,omitempty"`
	Deadline int64  `json:"absolute_expires_at,omitempty"`
	Error    string `json:"error,omitempty"`
}

// All state is memory-only. Restart intentionally invalidates renewal and device
// transactions, requiring fresh approval; it can never recreate/extend a session.
// The map lock never covers upstream calls. Per-entry gates serialize polling
// and session credential rotation/logout, with cancellable waits.
type Authority struct {
	mu              sync.Mutex
	config          Config
	provider        Provider
	signer          Signer
	now             func() time.Time
	audit           func(Audit)
	sessions        map[[32]byte]*session
	transactions    map[[32]byte]*transaction
	lastClockReadAt time.Time
	pendingStarts   int // Reserves capacity for Start calls awaiting the provider.
}

// New creates an in-memory authority. Configure it before accepting requests.
// Provider, Signer and audit must support concurrent calls. Audit runs without
// authority locks; a slow callback delays only its calling request.
func New(c Config, provider Provider, signer Signer, audit func(Audit)) (*Authority, error) {
	c = c.clone()
	if c.Validate() != nil || provider == nil || signer == nil || audit == nil {
		return nil, ErrDenied
	}
	return &Authority{
		config:       c,
		provider:     provider,
		signer:       signer,
		now:          time.Now,
		audit:        audit,
		sessions:     make(map[[32]byte]*session),
		transactions: make(map[[32]byte]*transaction),
	}, nil
}

func (a *Authority) clock() (time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if now.Before(a.lastClockReadAt) || now.UnixNano() < a.lastClockReadAt.UnixNano() {
		return now, ErrDenied
	}
	a.lastClockReadAt = now
	return now, nil
}

// cleanup runs under mu and only mutates idle entries.
func (a *Authority) cleanup(now time.Time) (events []Audit) {
	for k, t := range a.transactions {
		if !now.Before(t.expiresAt) && tryAcquire(t.gate) {
			delete(a.transactions, k)
			release(t.gate)
		}
	}
	for k, s := range a.sessions {
		if !now.Before(s.sessionExpiresAt) && tryAcquire(s.gate) {
			delete(a.sessions, k)
			s.credential = Credential{}
			events = append(events, a.auditEvent("expired", s, now))
			release(s.gate)
		}
	}
	return events
}

func (a *Authority) auditEvent(event string, s *session, now time.Time) Audit {
	return Audit{
		Event:     event,
		Issuer:    a.config.Issuer,
		ProjectID: a.config.ProjectID,
		UserID:    s.userID,
		SessionID: s.sessionID,
		Role:      s.role,
		At:        now.Unix(),
	}
}

// Lifecycle methods defer a closure so emit sees all events appended before
// return. They register it before deferring gate release: Go runs deferred calls
// in reverse order, so audit callbacks run after the gates have been released.
func (a *Authority) emit(events []Audit) {
	for _, e := range events {
		a.audit(e)
	}
}

// Start begins approval and retains the GitLab device code only at the broker.
func (a *Authority) Start(ctx context.Context) (DeviceResponse, error) {
	var events []Audit
	defer func() { a.emit(events) }()
	now, err := a.clock()
	if err != nil {
		return DeviceResponse{}, err
	}
	a.mu.Lock()
	events = append(events, a.cleanup(now)...)
	if len(a.transactions)+len(a.sessions)+a.pendingStarts >= 4096 {
		a.mu.Unlock()
		return DeviceResponse{}, ErrDenied
	}
	a.pendingStarts++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.pendingStarts--
		a.mu.Unlock()
	}()
	device, err := a.provider.Start(ctx)
	if err != nil {
		return DeviceResponse{}, ErrDenied
	}
	handle := random()
	a.mu.Lock()
	a.transactions[sha256.Sum256([]byte(handle))] = &transaction{
		gate:       make(chan struct{}, 1),
		device:     device,
		expiresAt:  now.Add(time.Duration(device.Expires) * time.Second),
		nextPollAt: now.Add(time.Duration(device.Interval) * time.Second),
	}
	a.mu.Unlock()
	return DeviceResponse{
		Transaction: handle,
		UserCode:    device.UserCode,
		URI:         device.URI,
		Expires:     device.Expires,
		Interval:    device.Interval,
	}, nil
}

// Poll consumes a successful device transaction once and fixes its deadline.
func (a *Authority) Poll(ctx context.Context, handle string) (Result, error) {
	var events []Audit
	defer func() { a.emit(events) }()
	key := sha256.Sum256([]byte(handle))
	a.mu.Lock()
	t := a.transactions[key]
	a.mu.Unlock()
	if t == nil {
		return Result{}, ErrDenied
	}
	if err := acquire(ctx, t.gate); err != nil {
		return Result{}, err
	}
	defer release(t.gate)
	a.mu.Lock()
	// Another poll may have consumed this transaction while we waited.
	valid := a.transactions[key] == t
	a.mu.Unlock()
	if !valid {
		return Result{}, ErrDenied
	}
	now, err := a.clock()
	if err != nil {
		return Result{}, err
	}
	a.mu.Lock()
	events = append(events, a.cleanup(now)...)
	a.mu.Unlock()
	if !now.Before(t.expiresAt) {
		a.deleteTransaction(key)
		return Result{}, ErrDenied
	}

	if now.Before(t.nextPollAt) {
		return Result{Error: "slow_down"}, nil
	}
	t.nextPollAt = now.Add(time.Duration(t.device.Interval) * time.Second)
	credential, err := a.provider.Poll(ctx, t.device.Code)
	if err != nil {
		a.deleteTransaction(key)
		return Result{}, ErrDenied
	}
	if credential.Error == "authorization_pending" || credential.Error == "slow_down" {
		if credential.Error == "slow_down" {
			t.device.Interval += 5
			t.nextPollAt = now.Add(time.Duration(t.device.Interval) * time.Second)
		}
		return Result{Error: credential.Error}, nil
	}
	defer a.deleteTransaction(key)
	// Record the start before identity/membership network calls. Latency never
	// grants extra session time. This transaction cannot be replayed after success.
	s := &session{
		gate:             make(chan struct{}, 1),
		credential:       credential,
		approvedAt:       now,
		sessionExpiresAt: now.Add(time.Duration(a.config.AbsoluteSeconds) * time.Second),
		sessionID:        random(),
		lastIssuedAt:     now,
	}
	verificationTime, err := a.clock()
	if err != nil {
		a.discard(ctx, s)
		return Result{}, err
	}
	identity, err := a.provider.Verify(ctx, credential.Access, verificationTime)
	if err != nil {
		a.discard(ctx, s)
		return Result{}, ErrDenied
	}
	s.userID = identity.UserID
	s.upstreamExpiresAt = identity.ExpiresAt
	if err = a.membership(ctx, s, now); err != nil {
		events = append(events, a.auditEvent("denied", s, now))
		a.discard(ctx, s)
		return Result{}, err
	}
	issuedAt, err := a.clock()
	if err != nil {
		a.discard(ctx, s)
		return Result{}, err
	}
	renewal := random()
	result, err := a.issue(s, issuedAt)
	if err != nil {
		a.discard(ctx, s)
		return Result{}, err
	}
	events = append(events, a.auditEvent("approved", s, issuedAt))
	a.mu.Lock()
	delete(a.transactions, key)
	a.sessions[sha256.Sum256([]byte(renewal))] = s
	a.mu.Unlock()
	result.Renewal = renewal
	return result, nil
}

func (a *Authority) membership(ctx context.Context, s *session, now time.Time) error {
	// Anchor freshness at request start, never response arrival. A slow response
	// cannot renew the membership budget.
	if s.membershipCheckedAt.IsZero() || now.Sub(s.membershipCheckedAt) >= time.Duration(a.config.CacheSeconds)*time.Second {
		level, err := a.provider.Membership(ctx, s.userID)
		if err != nil {
			return ErrDenied
		}
		r := a.config.clusterRole(level)
		if r == "" {
			return ErrDenied
		}
		s.role = r
		s.membershipCheckedAt = now
	}
	return nil
}

func (a *Authority) discard(ctx context.Context, s *session) {
	_ = a.provider.Revoke(ctx, s.credential.Access)
	s.credential = Credential{}
}

// Renew rechecks identity and membership without extending session approval.
func (a *Authority) Renew(ctx context.Context, handle string) (Result, error) {
	var events []Audit
	defer func() { a.emit(events) }()
	key := sha256.Sum256([]byte(handle))
	s, err := a.acquireSession(ctx, key)
	if err != nil {
		return Result{}, err
	}
	defer release(s.gate)
	now, err := a.clock()
	if err != nil {
		return Result{}, err
	}

	if !now.Before(s.sessionExpiresAt) {
		a.deleteSession(key)
		a.discard(ctx, s)
		events = append(events, a.auditEvent("expired", s, now))
		return Result{}, ErrDenied
	}
	// Every renewal performs live identity checks, including on cached membership.
	// Refresh once when necessary. Any ambiguous failure destroys renewal state;
	// an old rotated refresh token is never retried.
	candidate := s.credential
	if !now.Add(time.Duration(a.config.TokenSeconds+a.config.SkewSeconds) * time.Second).Before(s.upstreamExpiresAt) {
		credential, err := a.provider.Refresh(ctx, s.credential.Refresh)
		if err != nil || credential.Error != "" {
			a.deleteSession(key)
			a.discard(ctx, s)
			events = append(events, a.auditEvent("denied", s, now))
			return Result{}, ErrDenied
		}
		// Validate a rotated credential before atomically committing session state.
		candidate = credential
	}
	verificationTime, err := a.clock()
	if err != nil || !verificationTime.Before(s.sessionExpiresAt) {
		a.deleteSession(key)
		_ = a.provider.Revoke(ctx, candidate.Access)
		a.discard(ctx, s)
		return Result{}, ErrDenied
	}
	identity, err := a.provider.Verify(ctx, candidate.Access, verificationTime)
	if err != nil || identity.UserID != s.userID {
		_ = a.provider.Revoke(ctx, candidate.Access)
		a.deleteSession(key)
		a.discard(ctx, s)
		events = append(events, a.auditEvent("denied", s, now))
		return Result{}, ErrDenied
	}
	s.credential = candidate
	s.upstreamExpiresAt = identity.ExpiresAt
	if err = a.membership(ctx, s, now); err != nil {
		a.deleteSession(key)
		a.discard(ctx, s)
		events = append(events, a.auditEvent("denied", s, now))
		return Result{}, ErrDenied
	}
	issuedAt, err := a.clock()
	if err != nil {
		return Result{}, err
	}
	result, err := a.issue(s, issuedAt)
	if err != nil {
		return Result{}, err
	}
	events = append(events, a.auditEvent("renewed", s, issuedAt))
	return result, nil
}

func (a *Authority) issue(s *session, now time.Time) (Result, error) {
	skew := time.Duration(a.config.SkewSeconds) * time.Second
	expiry := now.Add(time.Duration(a.config.TokenSeconds) * time.Second)
	// Each deadline is independent. A slow lookup or refresh cannot buy time.
	limits := []time.Time{
		s.sessionExpiresAt.Add(-skew),
		s.upstreamExpiresAt.Add(-skew),
		s.membershipCheckedAt.Add(time.Duration(a.config.CacheSeconds+a.config.TokenSeconds) * time.Second),
	}
	for _, limit := range limits {
		if limit.Before(expiry) {
			expiry = limit
		}
	}
	// JWT timestamps have whole-second precision; reject an expiry that would
	// round down to the issuance second even if the time.Time is still future.
	if expiry.Unix() <= now.Unix() ||
		now.Before(s.lastIssuedAt) ||
		now.Before(s.membershipCheckedAt) ||
		now.Sub(s.membershipCheckedAt) > time.Duration(a.config.CacheSeconds)*time.Second {
		return Result{}, ErrDenied
	}
	s.lastIssuedAt = now
	claims := Claims{
		Issuer:              a.config.ClusterIssuer,
		Subject:             a.config.Issuer + "/user/" + decimal(s.userID),
		Audience:            []string{a.config.Audience},
		IssuedAt:            now.Unix(),
		NotBefore:           now.Unix(),
		ExpiresAt:           expiry.Unix(),
		ID:                  random(),
		Class:               "human",
		GitLabIssuer:        a.config.Issuer,
		ProjectID:           a.config.ProjectID,
		UserID:              s.userID,
		SessionID:           s.sessionID,
		ApprovedAt:          s.approvedAt.Unix(),
		SessionExp:          s.sessionExpiresAt.Unix(),
		MembershipCheckedAt: s.membershipCheckedAt.Unix(),
		Role:                s.role,
	}
	signed, err := a.signer.Sign(claims)
	if err != nil {
		return Result{}, ErrDenied
	}
	return Result{
		Access:   signed,
		Type:     "Bearer",
		Expires:  expiry.Unix() - now.Unix(),
		Deadline: s.sessionExpiresAt.Unix(),
	}, nil
}

// Logout removes renewal authority before attempting upstream revocation.
// Already-issued cluster tokens expire normally; they are not recallable JWTs.
func (a *Authority) Logout(ctx context.Context, handle string) error {
	var events []Audit
	defer func() { a.emit(events) }()
	key := sha256.Sum256([]byte(handle))
	s, err := a.acquireSession(ctx, key)
	if err != nil {
		return err
	}
	defer release(s.gate)
	a.deleteSession(key)

	err = a.provider.Revoke(ctx, s.credential.Access)
	s.credential = Credential{}
	events = append(events, a.auditEvent("logout", s, a.now()))
	return err
}

// Each gate is a channel with capacity one, used as a cancellable lock:
// sending a value acquires ownership; receiving it releases ownership. The
// empty struct carries no data. A full channel means another request owns it.
// Waiters can stop when their context is cancelled, unlike with sync.Mutex.
// Callers must release the map mutex before waiting so unrelated entries can
// still be used. After acquisition, they must recheck that the entry is live.
func acquire(ctx context.Context, gate chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case gate <- struct{}{}:
		// Cancellation and acquisition can become ready together. If cancelled,
		// give ownership back before returning.
		if err := ctx.Err(); err != nil {
			release(gate)
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// tryAcquire lets cleanup skip busy entries without waiting under the map mutex.
func tryAcquire(gate chan struct{}) bool {
	select {
	case gate <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(gate chan struct{}) { <-gate }

func (a *Authority) deleteTransaction(key [32]byte) {
	a.mu.Lock()
	delete(a.transactions, key)
	a.mu.Unlock()
}

func (a *Authority) deleteSession(key [32]byte) {
	a.mu.Lock()
	delete(a.sessions, key)
	a.mu.Unlock()
}

func (a *Authority) acquireSession(ctx context.Context, key [32]byte) (*session, error) {
	a.mu.Lock()
	s := a.sessions[key]
	a.mu.Unlock()
	if s == nil {
		return nil, ErrDenied
	}
	if err := acquire(ctx, s.gate); err != nil {
		return nil, err
	}
	a.mu.Lock()
	// Logout or cleanup may have removed this session while we waited.
	valid := a.sessions[key] == s
	a.mu.Unlock()
	if !valid {
		release(s.gate)
		return nil, ErrDenied
	}
	return s, nil
}
