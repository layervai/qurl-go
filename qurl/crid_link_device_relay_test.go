package qurl

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2s"

	"github.com/layervai/qurl-go/relayknock"
)

// The relay in the middle of a call made as a device.
//
// The relay carries both requests of the call and is not trusted. These tests
// pin what it can and what it cannot do to a reply. The relay here works with
// what a relay has: the packets it carries, the public layout of a packet,
// and, where a case says so, the PUBLIC key of the device. It never has a
// private key.
//
// The reason the two requests of a call differ is one field. A reply carries
// a digest of its header, and that digest is not keyed: it is a hash over a
// constant, the public key the reply is sealed to, and the header. For the
// first request that public key is random and nobody but the client knows it,
// so the relay cannot recompute the digest and any change to the header shows.
// For the second request it is the device's public key, which is long-lived
// and known outside the device. A relay that holds it can recompute the
// digest. What that lets it do, and what it still cannot do, is below.

// The layout of a reply header, as far as a relay needs it.
const (
	relayReplyHeaderSize   = 240
	relayReplyDigestOffset = 208
)

// relayHeaderDigest is the header digest of a reply as anybody can compute it
// who knows the public key the reply is sealed to.
func relayHeaderDigest(t *testing.T, recipientPublicKey, header []byte) []byte {
	t.Helper()
	hash, err := blake2s.New256(nil)
	if err != nil {
		t.Fatal(err)
	}
	hash.Write([]byte("NHP hashgen v.20230421@deepcloudsdp.com"))
	hash.Write(recipientPublicKey)
	hash.Write(header[:relayReplyDigestOffset])
	return hash.Sum(nil)
}

// relayRecognises reports whether a relay that holds publicKey can tell that
// reply is sealed to it.
func relayRecognises(t *testing.T, publicKey, reply []byte) bool {
	t.Helper()
	return bytes.Equal(relayHeaderDigest(t, publicKey, reply), reply[relayReplyDigestOffset:relayReplyHeaderSize])
}

// relayHeaderOnlyReply is what a relay can make of a reply when it holds the
// public key the reply is sealed to: the header alone, with the reply type the
// relay chooses and no body, and the digest computed again. Nothing in it is
// forged with a secret. The sealed fields of the header are the server's own.
func relayHeaderOnlyReply(t *testing.T, recipientPublicKey, reply []byte, replyType int) []byte {
	t.Helper()
	header := bytes.Clone(reply[:relayReplyHeaderSize])
	// The first four bytes are a mask. The next four are the type and the
	// body size under that mask.
	mask := binary.BigEndian.Uint32(header[0:4])
	binary.BigEndian.PutUint32(header[4:8], mask^(uint32(replyType)<<16))
	copy(header[relayReplyDigestOffset:], relayHeaderDigest(t, recipientPublicKey, header))
	return header
}

// meddlingRelay is a relay in the middle. It forwards each request to the
// peer, keeps the reply packets it carried, and may hand on another packet in
// place of the n-th reply of this relay.
type meddlingRelay struct {
	next HTTPDoer
	// replace returns the packet to hand on for the n-th reply, counted from
	// zero. A nil replace hands every reply on as it is.
	replace func(n int, reply []byte) []byte

	mu      sync.Mutex
	carried [][]byte
}

func (r *meddlingRelay) Do(req *http.Request) (*http.Response, error) {
	resp, err := r.next.Do(req)
	if err != nil {
		return nil, err
	}
	reply, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	n := len(r.carried)
	r.carried = append(r.carried, bytes.Clone(reply))
	r.mu.Unlock()
	if r.replace != nil && resp.StatusCode == http.StatusOK {
		reply = r.replace(n, reply)
	}
	resp.Body = io.NopCloser(bytes.NewReader(reply))
	resp.ContentLength = int64(len(reply))
	return resp, nil
}

// replies returns the reply packets the relay has carried, as the peer sent
// them.
func (r *meddlingRelay) replies() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.carried...)
}

// through returns cfg with the relay in front of the peer.
func (f *cridLinkFixture) through(relay *meddlingRelay) Config {
	relay.next = f.cfg.HTTPClient
	cfg := f.cfg
	cfg.HTTPClient = relay
	return cfg
}

// onlyReply returns a replace function that changes the n-th reply and hands
// every other reply on as it is.
func onlyReply(n int, change func(reply []byte) []byte) func(int, []byte) []byte {
	return func(i int, reply []byte) []byte {
		if i != n {
			return reply
		}
		return change(reply)
	}
}

// A relay that holds the device's public key can recognise the reply to the
// request under the device key, and so that request. It cannot recognise the
// reply to the first request, which is sealed to a random key. And it sees the
// size of every reply: a reply that carries a link is larger than a refusal.
func TestCRIDLinkAsDevice_RelayRecognisesOnlyTheRequestUnderTheDeviceKey(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	other := newCRIDLinkDevice(t)

	t.Run("a private resource", func(t *testing.T) {
		fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))
		relay := new(meddlingRelay)
		before := len(fixture.peer.seen())
		if _, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(relay)); err != nil {
			t.Fatal(err)
		}
		replies, knocks := relay.replies(), fixture.peer.requestsSince(before)
		if len(replies) != 2 || len(knocks) != 2 {
			t.Fatalf("the relay carried %d replies and the cell saw %d requests, want 2 and 2", len(replies), len(knocks))
		}

		// The check on the check: the digest function above is the right one.
		// The peer knows the random key of the first request. The relay does
		// not, but with it the digest of the first reply comes out.
		if !relayRecognises(t, knocks[0].devicePub, replies[0]) {
			t.Fatal("the test's digest function does not reproduce the digest of a reply; the results below would mean nothing")
		}

		// The first reply: not recognisable with the device's public key.
		if relayRecognises(t, device.public, replies[0]) {
			t.Fatal("the reply to the first request can be recognised with the device's public key")
		}
		// The second reply: recognisable with the device's public key, and
		// with no other.
		if !relayRecognises(t, device.public, replies[1]) {
			t.Fatal("the reply to the request under the device key cannot be recognised with the device's public key; the documented limit no longer holds, so update the documentation")
		}
		if relayRecognises(t, other.public, replies[1]) {
			t.Fatal("the reply to the request under the device key can be recognised with another device's public key")
		}
		// The sizes: "not found" first, then the link.
		if len(replies[1]) <= len(replies[0]) {
			t.Fatalf("the reply with the link is %d bytes and the refusal is %d bytes; the relay is documented to see the difference", len(replies[1]), len(replies[0]))
		}
	})

	// A request for a public resource is answered by the first request. No
	// reply of that call can be recognised with the device's public key.
	t.Run("a public resource", func(t *testing.T) {
		fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))
		relay := new(meddlingRelay)
		if _, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(relay)); err != nil {
			t.Fatal(err)
		}
		replies := relay.replies()
		if len(replies) != 1 {
			t.Fatalf("the relay carried %d replies, want 1", len(replies))
		}
		if relayRecognises(t, device.public, replies[0]) {
			t.Fatal("the reply to a request for a public resource can be recognised with the device's public key")
		}
	})
}

// A relay that holds the device's public key can make the call fail with an
// error that reads like an answer with nothing in it, whatever the server
// answered. Here the server issued a link every time.
//
// The call still makes exactly two requests. It does not ask a third time, and
// it returns no link and no "not found".
func TestCRIDLinkAsDevice_RelayCanTurnTheSecondReplyIntoNoUsableAnswer(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)

	// An old "busy" reply that the server once sent to this device key. The
	// relay carried it then and kept it.
	fixture.servePrivateResource(t, device, cridLinkAnswer{replyType: relayknock.TypeCookieChallenge})
	earlier := new(meddlingRelay)
	if _, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(earlier)); !errors.Is(err, ErrServerOverloaded) {
		t.Fatalf("the earlier call: error = %v, want ErrServerOverloaded from a server that is busy", err)
	}
	oldBusyReply := earlier.replies()[1]

	// From here on the server issues the link to the device.
	fixture.servePrivateResource(t, device, cridLinkIssued(t, fixture.link, fixture.info()))

	for _, tc := range []struct {
		name string
		// change is what the relay hands on in place of the second reply.
		change func(reply []byte) []byte
		want   string
	}{
		{
			// The relay holds the device's public key.
			"the header alone, as a busy reply",
			func(reply []byte) []byte {
				return relayHeaderOnlyReply(t, device.public, reply, relayknock.TypeCookieChallenge)
			},
			"overloaded",
		},
		{
			// The relay holds nothing but a packet it carried before.
			"an old busy reply to the same device, sent again",
			func([]byte) []byte { return oldBusyReply },
			"overloaded",
		},
		{
			"the header alone, as an answer with no body",
			func(reply []byte) []byte { return relayHeaderOnlyReply(t, device.public, reply, relayknock.TypeACK) },
			"protocol, malformed",
		},
		{
			"the header alone, as a reply of another type",
			func(reply []byte) []byte {
				return relayHeaderOnlyReply(t, device.public, reply, relayknock.TypeListResult)
			},
			"malformed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relay := &meddlingRelay{replace: onlyReply(1, tc.change)}
			before := len(fixture.peer.seen())
			issued, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(relay))
			knocks := fixture.peer.requestsSince(before)
			if len(knocks) != 2 {
				t.Fatalf("the cell saw %d requests, want exactly 2: no third request after an answer that is not usable", len(knocks))
			}
			assertRandomKeyRequest(t, "the first request", knocks[0], device, fixture.crid)
			assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
			if issued != nil {
				t.Fatal("a link was returned from a reply the relay made up")
			}
			if got := cridLinkErrorShape(err); got != tc.want {
				t.Fatalf("error = %v (%s), want %s", err, got, tc.want)
			}
			if errors.Is(err, ErrCRIDLinkNotFound) {
				t.Fatalf("error = %v: the relay made the call say \"not found\"", err)
			}
			// The server did issue the link. The relay carried it and dropped it.
			if got := len(relay.replies()); got != 2 {
				t.Fatalf("the relay carried %d replies, want 2", got)
			}
		})
	}
}

// What the relay cannot do to the reply under the device key, also when it
// holds the device's public key: forge a link, forge "not found", or change
// either. Every attempt ends in an error that is not a link and not
// ErrCRIDLinkNotFound, after exactly two requests.
func TestCRIDLinkAsDevice_RelayCannotForgeALinkOrARefusal(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)
	impostor, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := cridLinkIssued(t, fixture.link, fixture.info())
	notFound := cridLinkDenied(t, "52602")

	// Genuine replies of the server to this device key, from earlier calls.
	// The relay carried them and kept them.
	capture := func(forDevice cridLinkAnswer) (firstReply, secondReply []byte) {
		t.Helper()
		fixture.servePrivateResource(t, device, forDevice)
		relay := new(meddlingRelay)
		_, _ = RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(relay))
		replies := relay.replies()
		if len(replies) != 2 {
			t.Fatalf("the relay carried %d replies in the earlier call, want 2", len(replies))
		}
		return replies[0], replies[1]
	}
	_, oldLinkReply := capture(issued)
	oldFirstReply, oldNotFoundReply := capture(notFound)

	// A complete reply made up under a key that is not the cell's, sealed to
	// the device's public key and echoing the request. It is the most a relay
	// can make without a secret of the cell or of the device.
	madeUp := func(answer cridLinkAnswer) cridLinkAnswer {
		answer.sealedBy = impostor.Bytes()
		return answer
	}
	// spliced puts the sealed body of another genuine reply behind the header
	// of this one and computes the digest again. The header says the body
	// size, so the relay sets that too.
	spliced := func(reply, bodyOf []byte) []byte {
		header := bytes.Clone(reply[:relayReplyHeaderSize])
		body := bodyOf[relayReplyHeaderSize:]
		mask := binary.BigEndian.Uint32(header[0:4])
		binary.BigEndian.PutUint32(header[4:8], mask^(uint32(relayknock.TypeACK)<<16|uint32(len(body))))
		copy(header[relayReplyDigestOffset:], relayHeaderDigest(t, device.public, header))
		return append(header, body...)
	}

	for _, tc := range []struct {
		name string
		// server is what the server answers to the device key.
		server cridLinkAnswer
		// change is what the relay does to that reply. It is nil when the
		// reply is made up whole and the relay hands it on.
		change func(reply []byte) []byte
		want   string
	}{
		// The server said "not found". The relay wants a link.
		{"a link made up under another key", madeUp(issued), nil, "an error that matches nothing"},
		{"an old genuine link reply, sent again", notFound, func([]byte) []byte { return oldLinkReply }, "malformed"},
		{
			"the body of an old genuine link reply behind the new header",
			notFound, func(reply []byte) []byte { return spliced(reply, oldLinkReply) },
			"an error that matches nothing",
		},

		// The server issued a link. The relay wants "not found".
		{"\"not found\" made up under another key", madeUp(notFound), nil, "an error that matches nothing"},
		{"an old genuine \"not found\" reply, sent again", issued, func([]byte) []byte { return oldNotFoundReply }, "malformed"},
		{
			"the body of an old genuine \"not found\" reply behind the new header",
			issued, func(reply []byte) []byte { return spliced(reply, oldNotFoundReply) },
			"an error that matches nothing",
		},
		{
			"the body of the first reply of an old call behind the new header",
			issued, func(reply []byte) []byte { return spliced(reply, oldFirstReply) },
			"an error that matches nothing",
		},

		// The server issued a link. The relay changes it.
		{
			"one byte of the sealed body changed",
			issued, func(reply []byte) []byte {
				changed := bytes.Clone(reply)
				changed[len(changed)-1] ^= 0x01
				return changed
			},
			"an error that matches nothing",
		},
		{
			"the body cut short and the header fitted to it",
			issued, func(reply []byte) []byte { return spliced(reply, reply[:len(reply)-1]) },
			"an error that matches nothing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.servePrivateResource(t, device, tc.server)
			relay := new(meddlingRelay)
			if tc.change != nil {
				relay.replace = onlyReply(1, tc.change)
			}
			before := len(fixture.peer.seen())
			got, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(relay))
			knocks := fixture.peer.requestsSince(before)
			if len(knocks) != 2 {
				t.Fatalf("the cell saw %d requests, want exactly 2", len(knocks))
			}
			assertDeviceKeyRequest(t, "the second request", knocks[1], device, fixture.crid)
			if got != nil {
				t.Fatal("a link was returned from a reply the relay forged")
			}
			if errors.Is(err, ErrCRIDLinkNotFound) {
				t.Fatalf("error = %v: the relay forged \"not found\"", err)
			}
			if shape := cridLinkErrorShape(err); shape != tc.want {
				t.Fatalf("error = %v (%s), want %s", err, shape, tc.want)
			}
			assertNoDeviceKey(t, "the error", err.Error(), device)
		})
	}
}

// The first request is under a random key, and there the relay can do none of
// this. It does not know the public key the first reply is sealed to. The
// device's public key is the best guess it has, and it is the wrong one.
//
// Every attempt on the first reply fails to authenticate. It is not read as
// "busy" and not as "not found", and it does not lead to a second request. So
// a relay cannot make the device send its key.
func TestCRIDLinkAsDevice_RelayCannotChangeTheFirstReply(t *testing.T) {
	fixture := newCRIDLinkFixture(t)
	device := newCRIDLinkDevice(t)

	// An old "busy" reply that the server once sent to this device key.
	fixture.servePrivateResource(t, device, cridLinkAnswer{replyType: relayknock.TypeCookieChallenge})
	earlier := new(meddlingRelay)
	if _, err := RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(earlier)); !errors.Is(err, ErrServerOverloaded) {
		t.Fatalf("the earlier call: error = %v, want ErrServerOverloaded", err)
	}
	oldBusyReply := earlier.replies()[1]
	// An old "not found" that the server once sent to this device key.
	fixture.servePrivateResource(t, device, cridLinkDenied(t, "52602"))
	earlier = new(meddlingRelay)
	_, _ = RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, fixture.through(earlier))
	oldNotFoundReply := earlier.replies()[1]

	// The server would issue the link to anybody: a public resource.
	fixture.peer.respond(cridLinkIssued(t, fixture.link, fixture.info()))

	for _, tc := range []struct {
		name   string
		change func(reply []byte) []byte
	}{
		{"the header alone, as a busy reply", func(reply []byte) []byte {
			return relayHeaderOnlyReply(t, device.public, reply, relayknock.TypeCookieChallenge)
		}},
		{"the header alone, as an answer with no body", func(reply []byte) []byte {
			return relayHeaderOnlyReply(t, device.public, reply, relayknock.TypeACK)
		}},
		{"an old busy reply to the device key", func([]byte) []byte { return oldBusyReply }},
		{"an old \"not found\" reply to the device key", func([]byte) []byte { return oldNotFoundReply }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, call := range []struct {
				name string
				run  func(cfg Config) (*CRIDLink, error)
			}{
				{"RequestCRIDLinkAsDeviceWith", func(cfg Config) (*CRIDLink, error) {
					return RequestCRIDLinkAsDeviceWith(t.Context(), device.private, fixture.crid, cfg)
				}},
				// The call that takes no device key sends the same first
				// request, and the same holds for it.
				{"RequestCRIDLinkWith", func(cfg Config) (*CRIDLink, error) {
					return RequestCRIDLinkWith(t.Context(), fixture.crid, cfg)
				}},
			} {
				relay := &meddlingRelay{replace: onlyReply(0, tc.change)}
				before := len(fixture.peer.seen())
				issued, err := call.run(fixture.through(relay))
				if issued != nil {
					t.Fatalf("%s returned a link from a first reply the relay changed", call.name)
				}
				// It does not authenticate: none of the outcomes of a request.
				if got := cridLinkErrorShape(err); got != "an error that matches nothing" {
					t.Fatalf("%s error = %v (%s), want a reply that does not authenticate", call.name, err, got)
				}
				knocks := fixture.peer.requestsSince(before)
				if len(knocks) != 1 {
					t.Fatalf("%s: the cell saw %d requests, want exactly 1: a first reply that does not authenticate must not lead to a second request", call.name, len(knocks))
				}
				assertRandomKeyRequest(t, call.name+": the request", knocks[0], device, fixture.crid)
			}
		})
	}
}
