package nativeudp_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"
)

type assignmentCookieBehavior int

const (
	assignmentCookieSuccess assignmentCookieBehavior = iota
	assignmentCookieDirectResult
	assignmentCookieMalformed
	assignmentCookieWrongTransaction
	assignmentCookieWrongKey
	assignmentCookieCompressed
	assignmentCookieUnknownFlag
	assignmentCookieSecondChallenge
	assignmentCookieWrongResultCounter
	assignmentCookieWrongResultType
)

type assignmentCookieServer struct {
	t          *testing.T
	conn       *net.UDPConn
	serverPriv []byte
	altPriv    []byte
	agentPub   []byte
	cookie     []byte
	behavior   assignmentCookieBehavior
	done       chan struct{}

	mu       sync.Mutex
	packets  [][]byte
	requests []*relayknock.Reply
}

func newAssignmentCookieServer(t *testing.T, serverPriv, agentPub []byte, behavior assignmentCookieBehavior) *assignmentCookieServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	server := &assignmentCookieServer{
		t: t, conn: conn, serverPriv: serverPriv, altPriv: mustPriv(t), agentPub: agentPub,
		cookie: bytes.Repeat([]byte{0x5a}, 32), behavior: behavior, done: make(chan struct{}),
	}
	go server.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-server.done:
		case <-time.After(2 * time.Second):
			t.Error("assignment cookie server did not stop")
		}
	})
	return server
}

func (s *assignmentCookieServer) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *assignmentCookieServer) snapshot() ([][]byte, []*relayknock.Reply) {
	s.mu.Lock()
	defer s.mu.Unlock()
	packets := make([][]byte, len(s.packets))
	for i := range s.packets {
		packets[i] = bytes.Clone(s.packets[i])
	}
	requests := make([]*relayknock.Reply, len(s.requests))
	copy(requests, s.requests)
	return packets, requests
}

func (s *assignmentCookieServer) serve() {
	defer close(s.done)
	buffer := make([]byte, 4096)
	for {
		n, addr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := bytes.Clone(buffer[:n])
		s.mu.Lock()
		index := len(s.packets)
		s.packets = append(s.packets, packet)
		s.mu.Unlock()

		var request *relayknock.Reply
		switch index {
		case 0:
			request, err = relayknocktest.OpenInitiatorMessage(s.serverPriv, s.agentPub, packet)
		default:
			request, err = relayknocktest.OpenHubLSTCookieProofMessage(s.serverPriv, s.agentPub, s.cookie, packet)
		}
		if err != nil {
			s.t.Errorf("open assignment flight %d: %v", index, err)
			continue
		}
		s.mu.Lock()
		s.requests = append(s.requests, request)
		s.mu.Unlock()

		var reply []byte
		switch index {
		case 0:
			reply = s.challenge(request.Counter)
		case 1:
			reply = s.result(request.Counter)
		}
		if reply != nil {
			if _, err := s.conn.WriteToUDP(reply, addr); err != nil {
				s.t.Logf("write assignment flight %d: %v", index, err)
			}
		}
	}
}

func (s *assignmentCookieServer) challenge(counter uint64) []byte {
	body := []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter, base64.StdEncoding.EncodeToString(s.cookie)))
	serverPriv := s.serverPriv
	var flags uint16
	switch s.behavior {
	case assignmentCookieDirectResult:
		return s.buildReply(relayknock.TypeListResult, serverPriv, counter, []byte(`{"ok":true}`))
	case assignmentCookieMalformed:
		body = []byte(`{"trxId":`)
	case assignmentCookieWrongTransaction:
		body = []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter+1, base64.StdEncoding.EncodeToString(s.cookie)))
	case assignmentCookieWrongKey:
		serverPriv = s.altPriv
	case assignmentCookieCompressed:
		flags = 0x0002
		var compressed bytes.Buffer
		writer := zlib.NewWriter(&compressed)
		if _, err := writer.Write(body); err != nil {
			s.t.Errorf("compress challenge: %v", err)
			return nil
		}
		if err := writer.Close(); err != nil {
			s.t.Errorf("close challenge compressor: %v", err)
			return nil
		}
		body = compressed.Bytes()
	case assignmentCookieUnknownFlag:
		flags = 0x0008
	}
	if flags != 0 {
		return s.buildReplyWithFlags(relayknock.TypeCookieChallenge, flags, serverPriv, counter+99, body)
	}
	return s.buildReply(relayknock.TypeCookieChallenge, serverPriv, counter+99, body)
}

func (s *assignmentCookieServer) result(counter uint64) []byte {
	replyType := relayknock.TypeListResult
	body := []byte(`{"ok":true}`)
	switch s.behavior {
	case assignmentCookieSecondChallenge:
		replyType = relayknock.TypeCookieChallenge
		body = []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, counter, base64.StdEncoding.EncodeToString(s.cookie)))
	case assignmentCookieWrongResultCounter:
		counter++
	case assignmentCookieWrongResultType:
		replyType = relayknock.TypeACK
	}
	return s.buildReply(replyType, s.serverPriv, counter, body)
}

func (s *assignmentCookieServer) buildReply(replyType int, serverPriv []byte, counter uint64, body []byte) []byte {
	return s.buildReplyWithFlags(replyType, 0, serverPriv, counter, body)
}

func (s *assignmentCookieServer) buildReplyWithFlags(replyType int, flags uint16, serverPriv []byte, counter uint64, body []byte) []byte {
	inputs := &relayknock.KnockInputs{
		DeviceStaticPriv: serverPriv,
		ServerStaticPub:  s.agentPub,
		EphemeralPriv:    mustRand(s.t, 32),
		TimestampNanos:   uint64(time.Now().UnixNano()),
		Counter:          counter,
		Preamble:         mustPreamble(s.t),
		Body:             body,
	}
	var packet []byte
	var err error
	if flags == 0 {
		packet, err = relayknocktest.BuildReply(replyType, inputs)
	} else {
		packet, err = relayknocktest.BuildReplyWithFlags(replyType, flags, inputs)
	}
	if err != nil {
		s.t.Errorf("build assignment reply: %v", err)
		return nil
	}
	return packet
}

type assignmentCookieResolver struct{}

func (assignmentCookieResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}, nil
}

type assignmentCookieDialer struct {
	target string
	mu     sync.Mutex
	calls  int
}

func (d *assignmentCookieDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func (d *assignmentCookieDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func assignmentCookieSetup(t *testing.T, behavior assignmentCookieBehavior) (*assignmentCookieServer, nativeudp.Endpoint, nativeudp.Options, *assignmentCookieDialer) {
	t.Helper()
	serverPriv, serverPub := mustKeypair(t)
	devicePriv := mustPriv(t)
	server := newAssignmentCookieServer(t, serverPriv, pubOf(t, devicePriv), behavior)
	dialer := &assignmentCookieDialer{target: server.conn.LocalAddr().String()}
	return server,
		nativeudp.Endpoint{Host: "hub.nhp.layerv.ai", Port: server.port(), ServerStaticPub: serverPub},
		nativeudp.Options{DeviceStaticPriv: devicePriv, Resolver: assignmentCookieResolver{}, Dialer: dialer, Timeout: time.Second},
		dialer
}

func TestAssignmentList_CookieProofRoundTrip(t *testing.T) {
	server, endpoint, options, dialer := assignmentCookieSetup(t, assignmentCookieSuccess)
	body := []byte(`{"query":"cell_assignment","request_nonce":"one-logical-request"}`)
	reply, err := nativeudp.AssignmentList(context.Background(), endpoint, body, options)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.IsListResult() || string(reply.Body) != `{"ok":true}` {
		t.Fatalf("assignment reply = %#v", reply)
	}
	packets, requests := server.snapshot()
	if len(packets) != 2 || len(requests) != 2 || dialer.count() != 2 {
		t.Fatalf("packet/request/dial counts = %d/%d/%d, want 2/2/2", len(packets), len(requests), dialer.count())
	}
	if !bytes.Equal(requests[0].Body, body) || !bytes.Equal(requests[1].Body, body) {
		t.Fatalf("assignment bodies changed: %q / %q", requests[0].Body, requests[1].Body)
	}
	if requests[0].Counter == requests[1].Counter || requests[1].TimestampNanos <= requests[0].TimestampNanos || bytes.Equal(packets[0], packets[1]) {
		t.Fatalf("proof packet was not fresh: counters %d/%d timestamps %d/%d", requests[0].Counter, requests[1].Counter, requests[0].TimestampNanos, requests[1].TimestampNanos)
	}
}

func TestAssignmentList_DirectResultBeforeProofIsTerminal(t *testing.T) {
	server, endpoint, options, dialer := assignmentCookieSetup(t, assignmentCookieDirectResult)
	reply, err := nativeudp.AssignmentList(context.Background(), endpoint, []byte(`{"query":"cell_assignment"}`), options)
	if reply != nil || !errors.Is(err, relayknock.ErrMalformedReply) {
		t.Fatalf("assignment reply/error = %#v/%v, want nil ErrMalformedReply", reply, err)
	}
	packets, requests := server.snapshot()
	if len(packets) != 1 || len(requests) != 1 || dialer.count() != 1 {
		t.Fatalf("packet/request/dial counts = %d/%d/%d, want 1/1/1", len(packets), len(requests), dialer.count())
	}
}

func TestAssignmentList_ChallengeRejectsAreTerminal(t *testing.T) {
	for _, test := range []struct {
		name     string
		behavior assignmentCookieBehavior
		want     error
		flights  int
	}{
		{name: "malformed COK", behavior: assignmentCookieMalformed, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "wrong transaction", behavior: assignmentCookieWrongTransaction, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "untrusted Hub", behavior: assignmentCookieWrongKey, want: nativeudp.ErrServerUnauthenticated, flights: 1},
		{name: "result before proof", behavior: assignmentCookieDirectResult, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "compressed COK", behavior: assignmentCookieCompressed, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "unknown COK flag", behavior: assignmentCookieUnknownFlag, want: relayknock.ErrMalformedReply, flights: 1},
		{name: "second COK", behavior: assignmentCookieSecondChallenge, want: relayknock.ErrMalformedReply, flights: 2},
		{name: "wrong LRT counter", behavior: assignmentCookieWrongResultCounter, want: relayknock.ErrMalformedReply, flights: 2},
		{name: "wrong proof reply type", behavior: assignmentCookieWrongResultType, want: relayknock.ErrMalformedReply, flights: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, endpoint, options, dialer := assignmentCookieSetup(t, test.behavior)
			if reply, err := nativeudp.AssignmentList(context.Background(), endpoint, []byte(`{"query":"cell_assignment"}`), options); reply != nil || !errors.Is(err, test.want) {
				t.Fatalf("reply/error = %#v/%v, want nil/errors.Is(%v)", reply, err, test.want)
			}
			packets, _ := server.snapshot()
			if len(packets) != test.flights || dialer.count() != test.flights {
				t.Fatalf("packet/dial counts = %d/%d, want exactly %d with no third flight or address fallthrough", len(packets), dialer.count(), test.flights)
			}
		})
	}
}
