package relayknock

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestMatchedCounterEchoGolden(t *testing.T) {
	f := loadRelayKnockGolden(t)
	var extension struct {
		MatchedAck *conformance.RelayKnockCase `json:"matched_ack"`
	}
	if err := json.Unmarshal(conformance.RelayKnockVectors(), &extension); err != nil {
		t.Fatal(err)
	}
	switch f.SchemaVersion {
	case 1:
		if extension.MatchedAck != nil {
			t.Fatal("v1 cannot claim a matched ACK")
		}
		// Preserve published v1 adoption; its legacy decoder tests remain active.
		return
	case 2:
		if extension.MatchedAck == nil {
			t.Fatal("v2 must provide its matched ACK")
		}
	default:
		t.Fatalf("unsupported relay-knock schema %d", f.SchemaVersion)
	}
	ack := extension.MatchedAck
	if ack.ServerStaticPubHex != f.Knock.ServerStaticPubHex || ack.AgentStaticPrivHex != f.Knock.DeviceStaticPrivHex {
		t.Fatal("matched reply has different peers")
	}
	reply, err := DecryptReply(mustHex(t, ack.AgentStaticPrivHex), mustHex(t, ack.ServerStaticPubHex), mustHex(t, ack.PacketHex))
	if err != nil {
		t.Fatal(err)
	}
	requestCounter := mustDecimalU64(t, f.Knock.Counter)
	if !reply.IsACK() || reply.Counter != requestCounter || reply.Counter != mustHexU64(t, ack.CounterHex) {
		t.Fatalf("matched ACK must echo request counter %d, got type=%d counter=%d", requestCounter, reply.Type, reply.Counter)
	}
	if reply.TimestampNanos != mustDecimalU64(t, ack.TimestampNanos) || hex.EncodeToString(reply.Body) != ack.BodyHex {
		t.Fatal("matched reply changed authenticated timestamp/body")
	}
	legacy, err := DecryptReply(mustHex(t, f.Ack.AgentStaticPrivHex), mustHex(t, f.Ack.ServerStaticPubHex), mustHex(t, f.Ack.PacketHex))
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Counter == requestCounter {
		t.Fatal("legacy ACK must retain its unmatched negative-control counter")
	}
	t.Logf("schema v2 matched ACK opened with counter %d", reply.Counter)
}
