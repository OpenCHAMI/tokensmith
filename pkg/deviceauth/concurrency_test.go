package deviceauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Hooks block specific upstream operations without serializing the fake itself.
type concurrentProvider struct {
	verify  func(context.Context, string, time.Time) (Identity, error)
	refresh func(context.Context, string) (Credential, error)
	revoke  func(context.Context, string) error
	poll    func(context.Context, string) (Credential, error)
}

func (*concurrentProvider) Start(context.Context) (Device, error) {
	return Device{Code: random(), Expires: 300, Interval: 1}, nil
}
func (p *concurrentProvider) Poll(ctx context.Context, code string) (Credential, error) {
	if p.poll != nil {
		return p.poll(ctx, code)
	}
	return Credential{Access: code, Refresh: code}, nil
}
func (p *concurrentProvider) Refresh(ctx context.Context, token string) (Credential, error) {
	if p.refresh != nil {
		return p.refresh(ctx, token)
	}
	return Credential{Access: token + "rotated", Refresh: token + "rotated"}, nil
}
func (p *concurrentProvider) Verify(ctx context.Context, token string, now time.Time) (Identity, error) {
	if p.verify != nil {
		return p.verify(ctx, token, now)
	}
	return Identity{207, now.Add(time.Hour)}, nil
}
func (*concurrentProvider) Membership(context.Context, int64) (int, error) { return 40, nil }
func (p *concurrentProvider) Revoke(ctx context.Context, token string) error {
	if p.revoke != nil {
		return p.revoke(ctx, token)
	}
	return nil
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("operation blocked")
		var zero T
		return zero
	}
}
func asyncError(f func() error) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- f() }()
	return ch
}

func concurrentFixture(t *testing.T) (*fixture, *concurrentProvider, Result, Result) {
	t.Helper()
	x := setup(t)
	p := &concurrentProvider{}
	x.a.provider = p
	first, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	second, err := x.login(t)
	if err != nil {
		t.Fatal(err)
	}
	return x, p, first, second
}

func TestSlowRenewalIsolationAndCancellation(t *testing.T) {
	x, p, first, second := concurrentFixture(t)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	p.verify = func(ctx context.Context, _ string, now time.Time) (Identity, error) {
		close(entered)
		select {
		case <-unblock:
			return Identity{207, now.Add(time.Hour)}, nil
		case <-ctx.Done():
			return Identity{}, ctx.Err()
		}
	}
	slow := asyncError(func() error { _, err := x.a.Renew(context.Background(), first.Renewal); return err })
	receive(t, entered)
	// Another session can log out while the first verifies identity.
	unrelated := asyncError(func() error { return x.a.Logout(context.Background(), second.Renewal) })
	if err := receive(t, unrelated); err != nil {
		t.Fatal(err)
	}
	for _, logout := range []bool{false, true} {
		base, cancel := context.WithCancel(context.Background())
		ctx := &observedContext{Context: base, waiting: make(chan struct{})}
		waiting := asyncError(func() error {
			if logout {
				return x.a.Logout(ctx, first.Renewal)
			}
			_, err := x.a.Renew(ctx, first.Renewal)
			return err
		})
		receive(t, ctx.waiting)
		cancel()
		if err := receive(t, waiting); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled wait: %v", err)
		}
	}
	// Unauthenticated starts must also progress while identity verification is slow.
	if err := receive(t, asyncError(func() error { _, err := x.a.Start(context.Background()); return err })); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(unblock) })
	if err := receive(t, slow); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentLogoutWaitsForRotatedCredential(t *testing.T) {
	x, p, first, second := concurrentFixture(t)
	x.now = x.now.Add(time.Hour - 100*time.Second)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	var refreshes atomic.Int32
	p.refresh = func(context.Context, string) (Credential, error) {
		refreshes.Add(1)
		close(entered)
		<-unblock
		return Credential{Access: "rotated", Refresh: "rotated-refresh"}, nil
	}
	revoked := make(chan string, 4)
	p.revoke = func(_ context.Context, token string) error { revoked <- token; return nil }
	renew := asyncError(func() error { _, err := x.a.Renew(context.Background(), first.Renewal); return err })
	receive(t, entered)
	var logouts []<-chan error
	for i := 0; i < 2; i++ {
		ctx := &observedContext{Context: context.Background(), waiting: make(chan struct{})}
		logouts = append(logouts, asyncError(func() error { return x.a.Logout(ctx, first.Renewal) }))
		receive(t, ctx.waiting)
	}
	// An unrelated logout proceeds while refresh is blocked.
	if err := receive(t, asyncError(func() error { return x.a.Logout(context.Background(), second.Renewal) })); err != nil {
		t.Fatal(err)
	}
	receive(t, revoked)
	once.Do(func() { close(unblock) })
	if err := receive(t, renew); err != nil {
		t.Fatal(err)
	}
	successes := 0
	for _, done := range logouts {
		err := receive(t, done)
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
	}
	if successes != 1 || refreshes.Load() != 1 {
		t.Fatalf("logout successes=%d refreshes=%d", successes, refreshes.Load())
	}
	if token := receive(t, revoked); token != "rotated" {
		t.Fatalf("revoked %q instead of rotated credential", token)
	}
	if _, err := x.a.Renew(context.Background(), first.Renewal); !errors.Is(err, ErrDenied) {
		t.Fatalf("logout left session live: %v", err)
	}
	select {
	case token := <-revoked:
		t.Fatalf("duplicate revoke: %q", token)
	default:
	}
}

func TestSlowLogoutDoesNotBlockOtherSessions(t *testing.T) {
	x, p, first, second := concurrentFixture(t)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	p.revoke = func(context.Context, string) error { close(entered); <-unblock; return nil }
	slow := asyncError(func() error { return x.a.Logout(context.Background(), first.Renewal) })
	receive(t, entered)
	if err := receive(t, asyncError(func() error { _, err := x.a.Renew(context.Background(), second.Renewal); return err })); err != nil {
		t.Fatal(err)
	}
	if _, err := x.a.Renew(context.Background(), first.Renewal); !errors.Is(err, ErrDenied) {
		t.Fatalf("renewed during logout: %v", err)
	}
	once.Do(func() { close(unblock) })
	if err := receive(t, slow); err != nil {
		t.Fatal(err)
	}
}

// Done records when acquire has reached its cancellation select, so cancellation
// tests exercise an actual waiter rather than just a pre-cancelled request.
type observedContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *observedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestSlowPollSerializesTransactionAndAllowsCancellation(t *testing.T) {
	x, p, _, second := concurrentFixture(t)
	d, err := x.a.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	x.now = x.now.Add(time.Second)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	var polls atomic.Int32
	p.poll = func(_ context.Context, code string) (Credential, error) {
		polls.Add(1)
		close(entered)
		<-unblock
		return Credential{Access: code, Refresh: code}, nil
	}
	slow := asyncError(func() error { _, err := x.a.Poll(context.Background(), d.Transaction); return err })
	receive(t, entered)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &observedContext{Context: base, waiting: make(chan struct{})}
	waiting := asyncError(func() error { _, err := x.a.Poll(ctx, d.Transaction); return err })
	receive(t, ctx.waiting)
	cancel()
	if err := receive(t, waiting); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled poll: %v", err)
	}
	if err := receive(t, asyncError(func() error { _, err := x.a.Renew(context.Background(), second.Renewal); return err })); err != nil {
		t.Fatal(err)
	}
	once.Do(func() { close(unblock) })
	if err := receive(t, slow); err != nil {
		t.Fatal(err)
	}
	if _, err := x.a.Poll(context.Background(), d.Transaction); !errors.Is(err, ErrDenied) {
		t.Fatalf("replayed approval: %v", err)
	}
	if polls.Load() != 1 {
		t.Fatalf("upstream polled %d times", polls.Load())
	}
}

func TestAuditCallbackCanReenterAuthority(t *testing.T) {
	x, _, first, _ := concurrentFixture(t)
	x.a.audit = func(Audit) {
		if _, err := x.a.Start(context.Background()); err != nil {
			t.Error(err)
		}
	}
	if err := receive(t, asyncError(func() error { _, err := x.a.Renew(context.Background(), first.Renewal); return err })); err != nil {
		t.Fatal(err)
	}
}
