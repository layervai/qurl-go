package udpfence

import (
	"context"
	"errors"
	"testing"
)

// udpfence is the only channel through which qurl's recovery lifecycle can stop
// an in-flight native UDP write, so every assertion here is about failing closed
// on a missing context and about the guard's own error reaching the caller as
// the identical value — a wrapped or substituted error would strip the typed
// authority reason the lifecycle relies on.

// authorityError stands in for the lifecycle's typed authority error: the
// concrete type, not just the message, must survive Check.
type authorityError struct{ phase string }

func (e *authorityError) Error() string { return "lifecycle: unauthorized during " + e.phase }

// foreignKey is a different package's context key that happens to carry the same
// func() error shape. Check must not honor it: the fence's key type is private,
// so only With can arm a fence.
type foreignKey struct{}

func TestWith_PanicsOnNilInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		ctx   context.Context
		guard func() error
		want  string
	}{
		{name: "nil context", ctx: nil, guard: func() error { return nil }, want: "udpfence: nil context"},
		{name: "nil guard", ctx: context.Background(), guard: nil, want: "udpfence: nil guard"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				recovered := recover()
				if recovered == nil {
					t.Fatal("With returned instead of panicking on nil input")
				}
				got, ok := recovered.(string)
				if !ok || got != test.want {
					t.Fatalf("panic value = %v, want %q", recovered, test.want)
				}
			}()
			//nolint:staticcheck // deliberately passing nil to prove With fails closed.
			_ = With(test.ctx, test.guard)
		})
	}
}

func TestCheck_NilContextIsAnError(t *testing.T) {
	t.Parallel()
	//nolint:staticcheck // a nil context must be reported, never treated as unfenced.
	if err := Check(nil); err == nil {
		t.Fatal("Check(nil) = nil, want an error: a missing context must not read as an open fence")
	}
}

func TestCheck_UnfencedContextIsAllowed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		ctx  context.Context
	}{
		{name: "no fence", ctx: context.Background()},
		{name: "unrelated value", ctx: context.WithValue(context.Background(), foreignKey{}, func() error {
			return errors.New("another package's guard must not arm this fence")
		})},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := Check(test.ctx); err != nil {
				t.Fatalf("Check on an unfenced context = %v, want nil", err)
			}
		})
	}
}

func TestCheck_PropagatesGuardErrorUnchanged(t *testing.T) {
	t.Parallel()
	want := &authorityError{phase: "reknock"}
	got := Check(With(context.Background(), func() error { return want }))
	// Identity, not just errors.Is: the transport boundary must not wrap, rename,
	// or reclassify the lifecycle's authority error on its way out. errors.Is
	// would accept a wrapped error and so cannot express "returned unchanged".
	//nolint:errorlint // identity comparison is the assertion; errors.Is would defeat it.
	if got != error(want) {
		t.Fatalf("Check returned %#v, want the identical guard error %#v", got, want)
	}
	var typed *authorityError
	if !errors.As(got, &typed) || typed != want {
		t.Fatalf("errors.As recovered %#v, want the original typed error", typed)
	}
}

func TestCheck_RunsTheGuardOnEveryCall(t *testing.T) {
	t.Parallel()
	// The fence is consulted before DNS and again before every datagram write, so
	// a guard that closes mid-exchange must be observed by the very next Check.
	authority := errors.New("recovery deadline reached")
	calls := 0
	open := true
	ctx := With(context.Background(), func() error {
		calls++
		if open {
			return nil
		}
		return authority
	})

	if err := Check(ctx); err != nil {
		t.Fatalf("open fence = %v, want nil", err)
	}
	open = false
	if err := Check(ctx); !errors.Is(err, authority) {
		t.Fatalf("closed fence = %v, want the authority error", err)
	}
	if calls != 2 {
		t.Fatalf("guard invocations = %d, want one per Check (2)", calls)
	}
}

func TestWith_InnermostFenceWins(t *testing.T) {
	t.Parallel()
	outer := errors.New("outer fence")
	inner := errors.New("inner fence")
	ctx := With(context.Background(), func() error { return outer })
	if err := Check(With(ctx, func() error { return inner })); !errors.Is(err, inner) {
		t.Fatalf("nested fence = %v, want the innermost guard's error", err)
	}
	// Re-checking the parent still yields the outer guard: With derives a child
	// rather than mutating the fence already installed on ctx.
	if err := Check(ctx); !errors.Is(err, outer) {
		t.Fatalf("parent fence after nesting = %v, want the outer guard's error", err)
	}
}

func TestWith_CancellationAndFenceAreIndependent(t *testing.T) {
	t.Parallel()
	// The fence rides on a context value, so it must survive cancellation
	// plumbing: a caller that cancels still gets the authority reason from Check.
	authority := errors.New("assignment lease expired")
	ctx, cancel := context.WithCancel(With(context.Background(), func() error { return authority }))
	cancel()
	if err := Check(ctx); !errors.Is(err, authority) {
		t.Fatalf("fence under a cancelled context = %v, want the authority error", err)
	}
}
