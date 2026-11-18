package deviceauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fake struct {
	now                                 *time.Time
	level                               int
	user                                int64
	expiry                              time.Time
	outage, identityError, refreshError bool
	pending                             string
	checks, refreshes, revokes          int
	advance                             func()
}

func (f *fake) Start(context.Context) (Device, error) {
	return Device{Code: "device-secret", UserCode: "user-code", URI: "https://gitlab.example/oauth/device", Expires: 300, Interval: 5}, nil
}

func (f *fake) Poll(context.Context, string) (Credential, error) {
	return Credential{Access: "access-secret", Refresh: "refresh-secret", Type: "Bearer", Scope: "read_user", Expires: 7200, Error: f.pending}, nil
}

func (f *fake) Refresh(context.Context, string) (Credential, error) {
	f.refreshes++
	if f.refreshError {
		return Credential{}, errors.New("sensitive upstream error")
	}
	f.expiry = f.now.Add(7200 * time.Second)
	return Credential{Access: "rotated-secret", Refresh: "rotated-refresh", Type: "Bearer", Scope: "read_user", Expires: 7200}, nil
}

func (f *fake) Verify(context.Context, string, time.Time) (Identity, error) {
	if f.outage || f.identityError {
		return Identity{}, ErrDenied
	}
	return Identity{f.user, f.expiry}, nil
}

func (f *fake) Membership(context.Context, int64) (int, error) {
	f.checks++
	if f.advance != nil {
		f.advance()
	}
	if f.outage {
		return 0, ErrDenied
	}
	return f.level, nil
}

func (f *fake) Revoke(context.Context, string) error { f.revokes++; return nil }

type fixture struct {
	a       *Authority
	f       *fake
	k       *KeyRing
	now     time.Time
	audit   []Audit
	auditMu sync.Mutex
}

func setup(t *testing.T) *fixture {
	t.Helper()
	x := &fixture{now: time.Unix(1800000000, 0)}
	x.f = &fake{now: &x.now, level: 40, user: 207, expiry: x.now.Add(7200 * time.Second)}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	x.k, err = NewKeyRing("key-1", key)
	if err != nil {
		t.Fatal(err)
	}
	x.a, err = New(config(), x.f, x.k, func(a Audit) {
		x.auditMu.Lock()
		defer x.auditMu.Unlock()
		x.audit = append(x.audit, a)
	})
	if err != nil {
		t.Fatal(err)
	}
	x.a.now = func() time.Time { return x.now }
	return x
}

func (x *fixture) login(t *testing.T) (Result, error) {
	t.Helper()
	d, err := x.a.Start(ctx)
	if err != nil {
		return Result{}, err
	}
	x.now = x.now.Add(5 * time.Second)
	return x.a.Poll(ctx, d.Transaction)
}

func TestEffectiveRoles(t *testing.T) {
	for _, row := range []struct {
		name  string
		level int
		want  string
	}{
		{"owner receives admin", 50, "admin"},
		{"maintainer receives admin", 40, "admin"},
		{"developer receives operator", 30, "operator"},
		{"reporter receives viewer", 20, "viewer"},
		{"guest is denied", 10, ""},
		{"nonmember is denied", 0, ""},
		{"unknown intermediate level is denied", 15, ""},
		{"unknown higher level is denied", 60, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			x := setup(t)
			x.f.level = row.level
			r, err := x.login(t)
			if row.want == "" {
				if err == nil {
					t.Fatal("unauthorized role issued")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c, err := x.k.Verify(r.Access, config(), x.now)
			if err != nil || c.Role != row.want || c.UserID != 207 || c.ProjectID != 701 {
				t.Fatalf("wrong verified claims: %v", err)
			}
			b, _ := json.Marshal(x.audit)
			for _, secret := range []string{"access-secret", "refresh-secret", r.Access, r.Renewal, "device-secret", "user-code"} {
				if strings.Contains(string(b), secret) {
					t.Fatal("secret in audit")
				}
			}
		})
	}
}

func TestWorstCaseRevocationAndCacheEdge(t *testing.T) {
	x := setup(t)
	first, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	checked := x.now
	x.now = checked.Add(89999 * time.Millisecond)
	r, err := x.a.Renew(ctx, first.Renewal)
	if err != nil {
		t.Fatal(err)
	}
	if x.f.checks != 1 {
		t.Fatal("expected cached membership")
	}
	x.f.level = 10
	// Model the slowest allowed verifier clock: wall time minus 30 seconds.
	if _, err = x.k.Verify(r.Access, config(), checked.Add(268*time.Second+999*time.Millisecond)); err != nil {
		t.Fatal("token should remain valid through its established expiry")
	}
	if _, err = x.k.Verify(r.Access, config(), checked.Add(270*time.Second)); err == nil {
		t.Fatal("revocation budget exceeded")
	}
	x.now = checked.Add(90 * time.Second)
	if _, err = x.a.Renew(ctx, first.Renewal); err == nil {
		t.Fatal("cached allow at boundary")
	}
	if x.f.checks != 2 {
		t.Fatal("membership not rechecked")
	}
}

func TestDemotionAndOutage(t *testing.T) {
	x := setup(t)
	r, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	x.f.level = 20
	x.now = x.now.Add(90 * time.Second)
	next, err := x.a.Renew(ctx, r.Renewal)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x.k.Verify(next.Access, config(), x.now)
	if err != nil || c.Role != "viewer" {
		t.Fatal("demotion not applied")
	}
	x.f.outage = true
	if _, err = x.a.Renew(ctx, r.Renewal); err == nil {
		t.Fatal("outage used cached allow")
	}
	if _, err = x.k.Verify(next.Access, config(), x.now); err != nil {
		t.Fatal("outage retroactively broke issued token")
	}
	x.now = x.now.Add(210 * time.Second)
	if _, err = x.k.Verify(next.Access, config(), x.now); err == nil {
		t.Fatal("expired outage token accepted")
	}
}

func TestAbsoluteDeadlineAndRefresh(t *testing.T) {
	x := setup(t)
	r, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	deadline := r.Deadline
	for i := 0; i < 5; i++ {
		x.now = x.now.Add(7000 * time.Second)
		r2, err := x.a.Renew(ctx, r.Renewal)
		if err != nil {
			t.Fatal(err)
		}
		if r2.Deadline != deadline {
			t.Fatal("refresh moved deadline")
		}
	}
	x.now = time.Unix(deadline-31, 0)
	last, err := x.a.Renew(ctx, r.Renewal)
	if err != nil {
		t.Fatal(err)
	}
	if last.Expires != 1 {
		t.Fatalf("expiry plus skew not clamped: %d", last.Expires)
	}
	if _, err = x.k.Verify(last.Access, config(), time.Unix(deadline, 0)); err == nil {
		t.Fatal("deadline accepted")
	}
	x.now = time.Unix(deadline, 0)
	if _, err = x.a.Renew(ctx, r.Renewal); err == nil {
		t.Fatal("renewal at deadline")
	}
	if x.f.refreshes < 4 || x.f.revokes == 0 {
		t.Fatal("refresh/expiry cleanup not exercised")
	}
}

func TestRefreshIdentitySwitchAndAmbiguousFailure(t *testing.T) {
	for _, mode := range []string{"switch", "failure", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			x := setup(t)
			r, err := x.login(t)
			if err != nil {
				t.Fatal(err)
			}
			x.now = x.now.Add(7100 * time.Second)
			switch mode {
			case "switch":
				x.f.user = 208
			case "failure":
				x.f.refreshError = true
			case "invalid":
				x.f.identityError = true
			}
			if _, err = x.a.Renew(ctx, r.Renewal); err == nil {
				t.Fatal("unsafe renewal")
			}
			before := x.f.refreshes
			if _, err = x.a.Renew(ctx, r.Renewal); err == nil || x.f.refreshes != before {
				t.Fatal("retried ambiguous/rotated refresh")
			}
		})
	}
}

func TestConcurrentRefreshSerialized(t *testing.T) {
	x := setup(t)
	r, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	x.now = x.now.Add(7100 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := x.a.Renew(ctx, r.Renewal); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if x.f.refreshes != 1 {
		t.Fatalf("refresh replay %d", x.f.refreshes)
	}
}

func TestLogoutRestartClockAndSlowLookup(t *testing.T) {
	t.Run("logout", func(t *testing.T) {
		x := setup(t)
		r, err := x.login(t)
		if err != nil {
			t.Fatal(err)
		}
		if x.a.Logout(ctx, r.Renewal) != nil {
			t.Fatal("logout failed")
		}
		if _, err = x.a.Renew(ctx, r.Renewal); err == nil {
			t.Fatal("logout renewed")
		}
	})
	t.Run("restart", func(t *testing.T) {
		x := setup(t)
		r, err := x.login(t)
		if err != nil {
			t.Fatal(err)
		}
		a, err := New(config(), x.f, x.k, func(Audit) {})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.Renew(ctx, r.Renewal); err == nil {
			t.Fatal("missing state reconstructed")
		}
	})
	t.Run("backward-clock", func(t *testing.T) {
		x := setup(t)
		r, err := x.login(t)
		if err != nil {
			t.Fatal(err)
		}
		x.now = x.now.Add(-time.Second)
		if _, err = x.a.Renew(ctx, r.Renewal); err == nil {
			t.Fatal("clock uncertainty ignored")
		}
	})
	t.Run("slow-membership", func(t *testing.T) {
		x := setup(t)
		x.f.advance = func() { x.now = x.now.Add(91 * time.Second) }
		if _, err := x.login(t); err == nil {
			t.Fatal("response latency reset freshness")
		}
	})
}

func TestDeviceLifecycleAndStrictHTTP(t *testing.T) {
	x := setup(t)
	d, err := x.a.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	r, err := x.a.Poll(ctx, d.Transaction)
	if err != nil || r.Error != "slow_down" {
		t.Fatal("polling interval ignored")
	}
	x.now = x.now.Add(5 * time.Second)
	x.f.pending = "authorization_pending"
	r, err = x.a.Poll(ctx, d.Transaction)
	if err != nil || r.Error != x.f.pending {
		t.Fatal("pending not preserved")
	}
	x.now = x.now.Add(300 * time.Second)
	if _, err = x.a.Poll(ctx, d.Transaction); err == nil {
		t.Fatal("expired transaction accepted")
	}
	for _, body := range []string{`{"role":"admin"}`, `{"project_id":1}`, `{"issuer":"https://evil"}`, `{"access_token":"opaque"}`, `{"grant_type":"client_credentials"}`, `{} {}`, `{"transaction":1}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/device-auth/start", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		x.a.ServeHTTP(w, req)
		if w.Code != 400 {
			t.Fatalf("spoofed body accepted: %s", body)
		}
	}
}

// IDs must remain exact through signing and typed parsing, even above float64's
// integer precision. Small IDs would hide the old MapClaims round-trip loss.
func TestSessionPreservesLargeIdentityClaims(t *testing.T) {
	x := setup(t)
	c := config()
	c.ProjectID = 9007199254740993
	x.a.config = c
	x.f.user = 9007199254740995
	r, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := x.k.Verify(r.Access, c, x.now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ProjectID != c.ProjectID || claims.UserID != x.f.user {
		t.Fatalf("identity changed: project=%d user=%d", claims.ProjectID, claims.UserID)
	}
}

func TestMinimumCacheAllowsMembershipLatency(t *testing.T) {
	x := setup(t)
	c := config()
	c.CacheSeconds = 1
	x.a.config = c
	x.f.advance = func() { x.now = x.now.Add(100 * time.Millisecond) }
	r, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.k.Verify(r.Access, c, x.now); err != nil {
		t.Fatal(err)
	}
}

func TestRenewRejectsExpiryRoundedToCurrentSecond(t *testing.T) {
	x := setup(t)
	x.now = x.now.Add(500 * time.Millisecond)
	r, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	// The session cutoff minus skew is at .500; one whole second of JWT
	// lifetime remains at .900 of the preceding second.
	x.now = time.Unix(r.Deadline-31, 900000000)
	next, err := x.a.Renew(ctx, r.Renewal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.k.Verify(next.Access, config(), x.now); err != nil {
		t.Fatal(err)
	}
	// At .400 the time.Time cutoff is still in the future, but its integer
	// exp would equal iat and the resulting token would already be expired.
	x.now = time.Unix(r.Deadline-30, 400000000)
	if next, err := x.a.Renew(ctx, r.Renewal); !errors.Is(err, ErrDenied) || next.Access != "" {
		t.Fatalf("expected denial without a token: token_present=%t err=%v", next.Access != "", err)
	}
}
