package qurl_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

// newSilentUDPEndpoint binds a UDP socket that accepts datagrams and never
// replies. It is the client-side equivalent of a source-fenced security group:
// the write succeeds, nothing comes back, and no ICMP is generated.
func newSilentUDPEndpoint(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().String()
}

// sandboxHubPublicKey is the live sandbox Hub's X25519 public key, published at
// SSM /sandbox/nhp/control/hub/identity/public-key. It is non-secret and used
// here only so the fixture is the exact endpoint developers try to reach.
const sandboxHubPublicKey = "UhVQcrKoJ2LhQlRtuIItBjxXR2wA/VvZvTmqnzT+GS8="

func silentAssignmentHub(t *testing.T) qurl.HubBootstrap {
	t.Helper()
	return qurl.HubBootstrap{
		Host:               "hub.nhp.layerv.xyz",
		Port:               443,
		ServerPublicKeyB64: sandboxHubPublicKey,
	}
}

func testDevicePrivateKey(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return priv.Bytes()
}

// publicResolver returns one fixed public address so no real DNS is used and
// the SDK's public-address requirement is satisfied. The socket never reaches
// it: redirectDialer sends the datagram to the local silent endpoint instead.
type publicResolver struct{}

func (publicResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

// redirectDialer sends every dial to the silent local endpoint, so the logical
// destination stays the public hub name while the socket goes nowhere.
type redirectDialer struct{ target string }

func (d redirectDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func silentAssignmentTransport(t *testing.T, target string) nativeudp.Options {
	t.Helper()
	return nativeudp.Options{
		DeviceStaticPriv: testDevicePrivateKey(t),
		Resolver:         publicResolver{},
		Dialer:           redirectDialer{target: target},
		Timeout:          150 * time.Millisecond,
	}
}

// TestSilentHubIsDiagnosableWhenCallerDeadlineEndsTheWait reproduces the
// measured v0.3.0 failure against the source-fenced sandbox hub: the caller's
// own context deadline expires at the same moment as the internal assignment
// budget. That race previously returned a bare context.DeadlineExceeded, so the
// destination, the attempt count, and the transport cause were all lost and the
// caller could not tell a filtered network path from a dead hub, a DNS failure,
// or an unrelated timeout elsewhere in the program.
func TestSilentHubIsDiagnosableWhenCallerDeadlineEndsTheWait(t *testing.T) {
	t.Parallel()

	target := newSilentUDPEndpoint(t)
	hub := silentAssignmentHub(t)

	// The caller's own deadline ends the wait, which is what happens whenever the
	// caller's timeout is at or below the SDK's assignment budget — the probe used
	// exactly 30s against a 30s budget. Making it strictly shorter here pins the
	// same branch deterministically instead of racing two equal timers.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	_, err := qurl.FetchInitialAgentAssignment(ctx, hub, "probe-agent", "enrollment-credential-value",
		silentAssignmentTransport(t, target),
		qurl.WithAssignmentRetryBudget(4, 30*time.Second))
	if err == nil {
		t.Fatal("silent hub returned a successful assignment")
	}

	var silent *qurl.EndpointNoReplyError
	if !errors.As(err, &silent) {
		t.Fatalf("silent hub error = %T (%v); want *qurl.EndpointNoReplyError", err, err)
	}
	if !errors.Is(err, qurl.ErrEndpointNoReply) {
		t.Error("silent hub error does not match ErrEndpointNoReply")
	}
	// The caller's cancellation contract must survive: code that already branches
	// on context.DeadlineExceeded keeps working.
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Error("silent hub error dropped context.DeadlineExceeded from the chain")
	}
	// The distinguishing negatives the probe checked by hand.
	if errors.Is(err, nativeudp.ErrResolve) {
		t.Error("silent hub misreported a DNS resolution failure")
	}
	if errors.Is(err, nativeudp.ErrServerUnauthenticated) {
		t.Error("silent hub misreported a server authentication failure")
	}
	if errors.Is(err, qurl.ErrInvalidAssignmentConfig) {
		t.Error("silent hub misreported an invalid assignment config")
	}

	if silent.Endpoint != "hub.nhp.layerv.xyz:443" {
		t.Errorf("silent.Endpoint = %q; want the configured logical destination", silent.Endpoint)
	}
	if silent.Attempts < 1 {
		t.Errorf("silent.Attempts = %d; want at least 1", silent.Attempts)
	}
	if !errors.Is(silent.Last, nativeudp.ErrNoReply) {
		t.Errorf("silent.Last = %v; want a cause wrapping nativeudp.ErrNoReply", silent.Last)
	}
	// The message has to name the destination, or an operator reading a log line
	// still cannot act on it.
	if !strings.Contains(err.Error(), "hub.nhp.layerv.xyz:443") {
		t.Errorf("silent hub message does not name the destination: %v", err)
	}
	if strings.Contains(err.Error(), "enrollment-credential-value") {
		t.Fatal("silent hub error reflected the enrollment credential")
	}
}

// TestSilentHubIsDiagnosableWhenBudgetExpiresFirst covers the other half: the
// caller allows more time than the internal budget, so the bounded retry driver
// finishes on its own. The phase's public recovery taxonomy must be unchanged —
// the proof inventory pins it — while additionally carrying the silent-endpoint
// cause.
func TestSilentHubIsDiagnosableWhenBudgetExpiresFirst(t *testing.T) {
	t.Parallel()

	target := newSilentUDPEndpoint(t)
	hub := silentAssignmentHub(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := qurl.FetchInitialAgentAssignment(ctx, hub, "probe-agent", "enrollment-credential-value",
		silentAssignmentTransport(t, target),
		qurl.WithAssignmentRetryBudget(2, 900*time.Millisecond))
	if err == nil {
		t.Fatal("silent hub returned a successful assignment")
	}

	// Pinned taxonomy: unchanged.
	var recovery *qurl.AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) {
		t.Fatalf("silent hub error = %T (%v); want *qurl.AssignmentRecoveryRequiredError", err, err)
	}
	if !errors.Is(err, qurl.ErrAssignmentRecoveryRequired) {
		t.Error("silent hub error does not match ErrAssignmentRecoveryRequired")
	}
	if !errors.Is(err, nativeudp.ErrTransport) {
		t.Error("silent hub error does not match nativeudp.ErrTransport")
	}

	// Added signal: the same error now identifies what stayed quiet.
	var silent *qurl.EndpointNoReplyError
	if !errors.As(err, &silent) {
		t.Fatalf("recovery error does not carry *qurl.EndpointNoReplyError: %v", err)
	}
	if !errors.Is(err, qurl.ErrEndpointNoReply) {
		t.Error("recovery error does not match ErrEndpointNoReply")
	}
	if silent.Endpoint != "hub.nhp.layerv.xyz:443" {
		t.Errorf("silent.Endpoint = %q; want the configured logical destination", silent.Endpoint)
	}
	if strings.Contains(err.Error(), "enrollment-credential-value") {
		t.Fatal("silent hub error reflected the enrollment credential")
	}
}

// TestDialFailureIsNotReportedAsSilence guards the boundary: a path that fails
// to dial at all is not "the endpoint never replied", and must keep the plain
// recovery taxonomy rather than claiming a silent destination.
func TestDialFailureIsNotReportedAsSilence(t *testing.T) {
	t.Parallel()

	hub := silentAssignmentHub(t)
	transport := nativeudp.Options{
		DeviceStaticPriv: testDevicePrivateKey(t),
		Resolver:         publicResolver{},
		Dialer:           failingDialer{},
		Timeout:          150 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := qurl.FetchInitialAgentAssignment(ctx, hub, "probe-agent", "enrollment-credential-value",
		transport, qurl.WithAssignmentRetryBudget(2, 900*time.Millisecond))
	if err == nil {
		t.Fatal("failing dialer returned a successful assignment")
	}
	if errors.Is(err, qurl.ErrEndpointNoReply) {
		t.Errorf("dial failure was misreported as a silent endpoint: %v", err)
	}
	var recovery *qurl.AssignmentRecoveryRequiredError
	if !errors.As(err, &recovery) {
		t.Fatalf("dial failure error = %T (%v); want *qurl.AssignmentRecoveryRequiredError", err, err)
	}
}

type failingDialer struct{}

func (failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("injected dial failure")
}
