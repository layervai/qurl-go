package nativeudp_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// This file covers what a real customer network does to the transport and what
// injected dialers alone cannot show: datagrams that actually traverse an IPv6
// socket, an ICMP port-unreachable from a dead cell process, and several
// exchanges in flight at once. It reuses the loopback responder and dialers from
// transport_test.go. Run with -race.

// newIPv6LoopbackServer binds the NHP responder to a real udp6 socket on [::1].
// It skips rather than fails when the host has no IPv6 loopback (a developer
// machine may disable the family): that is an environment property, not a
// transport defect. QURL_GO_REQUIRE_IPV6 turns the skip into a failure so a CI
// runner that quietly loses the family cannot silently retire this coverage —
// a skipped test and a passing one are indistinguishable in a green run.
func newIPv6LoopbackServer(t *testing.T, serverPriv, agentPub []byte, b behavior) *fakeServer {
	t.Helper()
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		if os.Getenv("QURL_GO_REQUIRE_IPV6") != "" {
			t.Fatalf("QURL_GO_REQUIRE_IPV6 is set but the host has no usable IPv6 loopback: %v", err)
		}
		t.Skipf("host has no usable IPv6 loopback: %v", err)
	}
	_ = probe.Close()
	server := newFakeServerOn(t, "udp6", &net.UDPAddr{IP: net.IPv6loopback}, serverPriv, agentPub, b)
	if local := server.conn.LocalAddr().(*net.UDPAddr); local.IP.To4() != nil {
		t.Fatalf("responder bound %s, want an IPv6 socket", local)
	}
	return server
}

// refusedUDPTarget binds a loopback UDP port and closes it, so a *connected*
// socket writing there receives ICMP port-unreachable (ECONNREFUSED) instead of
// silence — what an agent sees when the cell process is down but the host is up.
// It probes the behavior first and skips on a platform that does not deliver the
// signal, because the fallback would be a timing-only assertion.
func refusedUDPTarget(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	target := listener.LocalAddr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	if probeErr := probeRefused(t, target); !errors.Is(probeErr, syscall.ECONNREFUSED) {
		t.Skipf("platform does not deliver ICMP port-unreachable to a connected UDP socket (closed port answered %v); asserting on latency alone would be flaky", probeErr)
	}
	return target
}

// probeRefused reports what a connected socket observes when it writes to target.
// It is also used after an exchange to distinguish a real misclassification from
// the rare case where another listener claimed the released ephemeral port.
func probeRefused(t *testing.T, target string) error {
	t.Helper()
	probe, err := (&net.Dialer{}).DialContext(context.Background(), "udp", target)
	if err != nil {
		t.Fatalf("dial closed port %s: %v", target, err)
	}
	defer func() { _ = probe.Close() }()
	if err := probe.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set probe deadline: %v", err)
	}
	if _, err := probe.Write([]byte("probe")); err != nil {
		return err // some stacks surface the refusal on a later write
	}
	_, err = probe.Read(make([]byte, 64))
	return err
}

// TestExchange_IPv6RoundTrip drives a complete authenticated exchange over a real
// udp6 socket. publicRoutableAddress rejects ::1, so the resolver returns an
// allocated public IPv6 address and the routing dialer maps it to the [::1]
// responder; the routing table is keyed on the exact bracketed address the
// transport builds, so a host/port join that mishandles IPv6 fails to dial.
func TestExchange_IPv6RoundTrip(t *testing.T) {
	t.Parallel()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	server := newIPv6LoopbackServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal)

	resolved := netip.MustParseAddr("2606:4700:4700::1111")
	const assignedPort = 443
	dialer := &addressRoutingDialer{routes: map[string]string{
		netip.AddrPortFrom(resolved, assignedPort).String(): server.conn.LocalAddr().String(),
	}}
	ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
	opts := nativeudp.Options{
		DeviceStaticPriv: devicePriv,
		Resolver:         resolverReturning([]netip.Addr{resolved}),
		Dialer:           dialer,
		Timeout:          2 * time.Second,
	}

	reply, err := nativeudp.Knock(context.Background(), ep, []byte(`{"family":6}`), opts)
	if err != nil {
		t.Fatalf("Knock over IPv6: %v", err)
	}
	if !reply.IsACK() || string(reply.Body) != `{"ok":true}` {
		t.Fatalf("IPv6 reply type/body = %d/%q, want ACK/{\"ok\":true}", reply.Type, reply.Body)
	}
	// A udp4 client socket cannot reach a listener bound to [::1], so a completed
	// round trip here proves the datagram crossed an AF_INET6 socket.
	if got := server.receivedCount(); got != 1 {
		t.Fatalf("IPv6 responder received %d datagrams, want 1", got)
	}
}

// TestExchange_DualStackFallsThroughAcrossFamilies pins that address fallback is
// family-agnostic and preserves resolver order: whichever family DNS lists first,
// an unreachable first address must fall through to the reachable second one.
func TestExchange_DualStackFallsThroughAcrossFamilies(t *testing.T) {
	t.Parallel()
	v4 := netip.MustParseAddr("8.8.8.8")
	v6 := netip.MustParseAddr("2606:4700:4700::1111")
	for _, test := range []struct {
		name     string
		resolved []netip.Addr
		reachV6  bool // whether the reachable (second) address is the IPv6 one
	}{
		{name: "AAAA first, A reachable", resolved: []netip.Addr{v6, v4}, reachV6: false},
		{name: "A first, AAAA reachable", resolved: []netip.Addr{v4, v6}, reachV6: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			serverPriv, serverPub := mustKeypair(t)
			devicePriv := mustPriv(t)
			agentPub := pubOf(t, devicePriv)
			var server *fakeServer
			if test.reachV6 {
				server = newIPv6LoopbackServer(t, serverPriv, agentPub, behaviorNormal)
			} else {
				server = newFakeServer(t, serverPriv, agentPub, behaviorNormal)
			}

			const assignedPort = 443
			// Only the second resolved address has a route; the first fails to dial,
			// which is the transport fault that must trigger fallthrough.
			reachable := test.resolved[1]
			dialer := &addressRoutingDialer{routes: map[string]string{
				netip.AddrPortFrom(reachable, assignedPort).String(): server.conn.LocalAddr().String(),
			}}
			ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
			opts := nativeudp.Options{
				DeviceStaticPriv: devicePriv,
				Resolver:         resolverReturning(test.resolved),
				Dialer:           dialer,
				Timeout:          2 * time.Second,
			}

			reply, err := nativeudp.Knock(context.Background(), ep, nil, opts)
			if err != nil {
				t.Fatalf("Knock did not fall through to the %s address: %v", reachable, err)
			}
			if !reply.IsACK() {
				t.Fatalf("reply type = %d, want ACK", reply.Type)
			}
			if got := server.receivedCount(); got != 1 {
				t.Fatalf("reachable responder received %d datagrams, want 1", got)
			}
		})
	}
}

// TestExchange_ConnectionRefusedIsRetryableTransport covers the dead-cell case: a
// connected UDP socket surfaces ECONNREFUSED instead of timing out, and that is a
// transport miss (retry the next address) — never a received-but-unauthenticated
// datagram, which would be terminal.
func TestExchange_ConnectionRefusedIsRetryableTransport(t *testing.T) {
	t.Parallel()
	refused := refusedUDPTarget(t)
	dead := netip.MustParseAddr("9.9.9.9")
	live := netip.MustParseAddr("149.112.112.112")
	const assignedPort = 443

	t.Run("falls through to the next address", func(t *testing.T) {
		t.Parallel()
		serverPriv, serverPub := mustKeypair(t)
		devicePriv := mustPriv(t)
		server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal)
		dialer := &addressRoutingDialer{routes: map[string]string{
			netip.AddrPortFrom(dead, assignedPort).String(): refused,
			netip.AddrPortFrom(live, assignedPort).String(): server.conn.LocalAddr().String(),
		}}
		ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
		opts := nativeudp.Options{
			DeviceStaticPriv: devicePriv,
			Resolver:         resolverReturning([]netip.Addr{dead, live}),
			Dialer:           dialer,
			Timeout:          10 * time.Second,
		}

		reply, err := nativeudp.Knock(context.Background(), ep, nil, opts)
		if err != nil || !reply.IsACK() {
			t.Fatalf("refused first address did not fall through: reply=%v err=%v", reply, err)
		}
		if got := server.receivedCount(); got != 1 {
			t.Fatalf("live responder received %d datagrams, want 1", got)
		}
	})

	t.Run("every address refused is ErrTransport", func(t *testing.T) {
		t.Parallel()
		_, serverPub := mustKeypair(t)
		devicePriv := mustPriv(t)
		dialer := &addressRoutingDialer{routes: map[string]string{
			netip.AddrPortFrom(dead, assignedPort).String(): refused,
		}}
		ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
		opts := nativeudp.Options{
			DeviceStaticPriv: devicePriv,
			Resolver:         resolverReturning([]netip.Addr{dead}),
			Dialer:           dialer,
			// A long socket deadline: the refusal, not the timeout, must end this.
			Timeout: 10 * time.Second,
		}

		start := time.Now()
		_, err := nativeudp.Knock(context.Background(), ep, nil, opts)
		if !errors.Is(err, nativeudp.ErrTransport) {
			t.Fatalf("error = %v, want ErrTransport", err)
		}
		if errors.Is(err, nativeudp.ErrServerUnauthenticated) {
			t.Fatalf("ICMP refusal was classified as a received datagram: %v", err)
		}
		// The refusal must reach the caller as the ICMP signal it is, not as an
		// expired socket deadline; refusedUDPTarget already proved the platform
		// delivers it, so this is an exact assertion rather than a timing one.
		if !errors.Is(err, syscall.ECONNREFUSED) {
			// A released ephemeral port can in principle be claimed by another
			// listener mid-test. Re-probe before failing so that becomes a skip
			// rather than a spurious failure.
			if probeErr := probeRefused(t, refused); !errors.Is(probeErr, syscall.ECONNREFUSED) {
				t.Skipf("the reserved port %s stopped refusing mid-test (now %v); skipping rather than asserting against a moving target", refused, probeErr)
			}
			t.Fatalf("error = %v, want a wrapped ECONNREFUSED", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("refused exchange took %s; it waited for the socket deadline", elapsed)
		}
	})
}

// TestExchange_ConcurrentClients runs several exchanges against one endpoint at
// once. Beyond the race detector, each client sends a distinct body that the
// responder echoes, so a reply buffer shared across live exchanges would surface
// as a client reading another client's body rather than as silent corruption.
func TestExchange_ConcurrentClients(t *testing.T) {
	t.Parallel()
	const clients = 8
	dead := netip.MustParseAddr("9.9.9.9")
	live := netip.MustParseAddr("149.112.112.112")
	const assignedPort = 443

	for _, test := range []struct {
		name     string
		resolved []netip.Addr
	}{
		{name: "single address", resolved: []netip.Addr{live}},
		// Every exchange also performs a serial fallback, so the reuse of one
		// receive buffer across attempts runs concurrently with seven others.
		{name: "with address fallback", resolved: []netip.Addr{dead, live}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			serverPriv, serverPub := mustKeypair(t)
			devicePriv := mustPriv(t)
			server := newFakeServer(t, serverPriv, pubOf(t, devicePriv), behaviorNormal, withBodyEcho)
			dialer := &addressRoutingDialer{routes: map[string]string{
				netip.AddrPortFrom(live, assignedPort).String(): server.conn.LocalAddr().String(),
			}}
			ep := nativeudp.Endpoint{Host: "cell0.nhp.test", Port: assignedPort, ServerStaticPub: serverPub}
			// One Options value shared by every goroutine: DeviceStaticPriv is
			// read-only for the duration of an exchange, which the race detector
			// enforces here.
			opts := nativeudp.Options{
				DeviceStaticPriv: devicePriv,
				Resolver:         resolverReturning(test.resolved),
				Dialer:           dialer,
				Timeout:          10 * time.Second,
			}

			var wg sync.WaitGroup
			failures := make(chan error, clients)
			for client := range clients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					// Bodies differ in both content and length so an aliased buffer
					// cannot coincidentally produce a matching reply.
					body := []byte(fmt.Sprintf(`{"client":%d,"pad":%q}`, client, strings.Repeat("p", client*37)))
					reply, err := nativeudp.Knock(context.Background(), ep, body, opts)
					switch {
					case err != nil:
						failures <- fmt.Errorf("client %d: %w", client, err)
					case !reply.IsACK():
						failures <- fmt.Errorf("client %d: reply type = %d, want ACK", client, reply.Type)
					case !bytes.Equal(reply.Body, body):
						failures <- fmt.Errorf("client %d received a reply for another exchange: %q", client, reply.Body)
					}
				}()
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			if got := server.receivedCount(); got != clients {
				t.Fatalf("responder received %d datagrams, want %d", got, clients)
			}
		})
	}
}

// TestExchange_ConcurrentClientsShareNoReplyBufferAcrossHelpers runs the mixed
// traffic a busy agent produces — knock, list, and register at once — so a
// cross-exchange buffer would also show up as a reply-type confusion.
func TestExchange_ConcurrentClientsShareNoReplyBufferAcrossHelpers(t *testing.T) {
	t.Parallel()
	_, ep, opts := newLoopbackExchange(t, behaviorNormal)
	opts.Timeout = 10 * time.Second

	helpers := []struct {
		name    string
		reqType int
		accept  func(*relayknock.Reply) bool
	}{
		{name: "knock", reqType: relayknock.TypeKnock, accept: (*relayknock.Reply).IsACK},
		{name: "list", reqType: relayknock.TypeListRequest, accept: (*relayknock.Reply).IsListResult},
		{name: "register", reqType: relayknock.TypeRegister, accept: (*relayknock.Reply).IsRegisterAck},
		{name: "exit", reqType: relayknock.TypeExit, accept: (*relayknock.Reply).IsACK},
	}
	var wg sync.WaitGroup
	failures := make(chan error, len(helpers)*4)
	for round := range 4 {
		for _, helper := range helpers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				reply, err := nativeudp.Exchange(context.Background(), ep, helper.reqType, nil, opts)
				if err != nil {
					failures <- fmt.Errorf("round %d %s: %w", round, helper.name, err)
					return
				}
				if !helper.accept(reply) {
					failures <- fmt.Errorf("round %d %s: reply type %d is not the answer to request type %d", round, helper.name, reply.Type, helper.reqType)
				}
			}()
		}
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
