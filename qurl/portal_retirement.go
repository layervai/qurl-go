package qurl

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/layervai/qurl-go/internal/cryptoutil"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/nativeudp"
)

type portalRetirement struct {
	mu            sync.Mutex
	receipt       NativeSessionReceipt
	key, server   []byte
	relay         string
	client        HTTPDoer
	endpoint      *nativeudp.Endpoint
	nativeOptions *nativeudp.Options
	terminal      *NativeSessionRetirement
}

func newPortalRetirement(ack *serverKnockAckMsg, key, server []byte, relay string, client HTTPDoer) (*portalRetirement, error) {
	var issued int64
	var attempt uint64
	if json.Unmarshal(ack.IssuedAt, &issued) != nil || json.Unmarshal(ack.RunAttempt, &attempt) != nil || issued <= 0 || attempt == 0 || !validAssignmentCellID(ack.CellID) || ValidateCycleRunID(ack.RunID) != nil || !ack.SessionID.Present || ack.SessionID.Value == 0 || len(key) != 32 || len(server) != 32 {
		return nil, fmt.Errorf("%w: missing native cleanup receipt", ErrMalformedReply)
	}
	return &portalRetirement{receipt: NativeSessionReceipt{CellID: ack.CellID, SessionID: ack.SessionID.Value, SessionIssuedAtMillis: issued, RunID: ack.RunID, RunAttempt: attempt}, key: append([]byte(nil), key...), server: append([]byte(nil), server...), relay: relay, client: client}, nil
}

// RetireSession sends the existing authenticated exact-session EXT using this
// handle's original key, cell and immutable receipt. It never reopens access.
// A closing reply is not cleanup completion. Repeat with a bounded context until
// State is closed; otherwise keep the fixture unresolved. Terminal success wipes
// the retained key. Calls serialize, and a later assignment is never consulted.
func (h *ResourceHandle) RetireSession(ctx context.Context) (*NativeSessionRetirement, error) {
	if h == nil || h.retirement == nil {
		return nil, fmt.Errorf("%w: native cleanup was not retained", ErrInvalidNativeKnockInput)
	}
	r := h.retirement
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminal != nil {
		result := *r.terminal
		return &result, nil
	}
	if len(r.key) == 0 {
		return nil, fmt.Errorf("%w: native cleanup key was released", ErrInvalidNativeKnockInput)
	}
	receipt := r.receipt
	body, err := json.Marshal(nativeExactSessionCloseBody{HeaderType: relayknock.TypeExit, AuthServiceID: "agent", CellID: receipt.CellID, SessionID: receipt.SessionID, SessionIssuedAtMillis: receipt.SessionIssuedAtMillis, RunID: receipt.RunID, RunAttempt: receipt.RunAttempt})
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Wipe(body)
	var reply *relayknock.Reply
	if r.endpoint != nil {
		opts := nativeudp.Options{DeviceStaticPriv: r.key}
		if r.nativeOptions != nil {
			opts.Resolver = r.nativeOptions.Resolver
			opts.Dialer = r.nativeOptions.Dialer
		}
		reply, err = nativeudp.Exit(ctx, *r.endpoint, body, opts)
	} else {
		eph := make([]byte, 32)
		defer cryptoutil.Wipe(eph)
		var entropy [12]byte
		if _, err = rand.Read(eph); err != nil {
			return nil, err
		}
		if _, err = rand.Read(entropy[:]); err != nil {
			return nil, err
		}
		counter := binary.BigEndian.Uint64(entropy[:8])
		packet, buildErr := relayknock.BuildMessage(relayknock.TypeExit, &relayknock.KnockInputs{DeviceStaticPriv: r.key, ServerStaticPub: r.server, EphemeralPriv: eph, TimestampNanos: uint64(time.Now().UnixNano()), Counter: counter, Preamble: binary.BigEndian.Uint32(entropy[8:]), Body: body})
		if buildErr != nil {
			return nil, buildErr
		}
		var wire []byte
		wire, err = relayknock.RelayPost(ctx, r.client, r.relay, relayknock.PubKeyFingerprint(r.server), packet)
		if err == nil {
			reply, err = relayknock.DecryptReply(r.key, r.server, wire)
		}
		if err == nil && (reply == nil || !reply.IsACK() || reply.Counter != counter) {
			err = fmt.Errorf("%w: native cleanup counter or type", ErrMalformedReply)
		}
	}
	if err != nil {
		return nil, normalizeRelayError(err, ErrMalformedReply)
	}
	result, err := consumeNativeExactSessionCloseReply(reply, receipt)
	if err == nil && result.State == "closed" {
		cryptoutil.Wipe(r.key)
		r.key = nil
		terminal := *result
		r.terminal = &terminal
	}
	return result, err
}
