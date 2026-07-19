// Package udpfence carries an internal, fail-closed authorization check from a
// lifecycle transaction to the native UDP write boundary.
package udpfence

import (
	"context"
	"errors"
)

type contextKey struct{}

// With returns a child context whose guard is checked before DNS and again
// immediately before every UDP datagram write. It is internal because the
// public nativeudp transport has no general policy surface; qurl's finite
// recovery lifecycle is its only consumer.
func With(ctx context.Context, guard func() error) context.Context {
	if ctx == nil {
		panic("udpfence: nil context")
	}
	if guard == nil {
		panic("udpfence: nil guard")
	}
	return context.WithValue(ctx, contextKey{}, guard)
}

// Check runs the current fence, if any. An error is returned unchanged so the
// lifecycle's typed authority error survives the transport boundary.
func Check(ctx context.Context) error {
	if ctx == nil {
		return errors.New("udpfence: nil context")
	}
	guard, _ := ctx.Value(contextKey{}).(func() error)
	if guard == nil {
		return nil
	}
	return guard()
}
