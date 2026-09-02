package signaling

import (
	"testing"
)

// Everything here reads bytes that arrived over a WebSocket from an
// authenticated but otherwise untrusted peer.
//
// The amplification property is the one worth pinning down: an envelope is
// accepted at one size and re-encoded before being relayed, and JSON escaping
// can make the second bigger than the first. A peer that could reliably grow a
// frame on its way out would be handing itself a multiplier against every other
// member of the room.
func FuzzRelayEnvelope(f *testing.F) {
	f.Add([]byte(`{"type":"offer","to":"0011223344556677","payload":{"sdp":"v=0"}}`))
	f.Add([]byte(`{"type":"ice-candidate","to":"0011223344556677","payload":{}}`))
	f.Add([]byte(`{"type":"offer","to":"0011223344556677","payload":{"sdp":"\"\"\"\""}}`))
	f.Add([]byte(`{"type":"offer","to":"0011223344556677","payload":"\ud800"}`))
	f.Add([]byte(`{"type":"answer","to":"0011223344556677","payload":[1,2,3]}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// The real sequence: a frame is decoded, stamped, re-encoded, and read
		// again by the far peer. Anything constructed by hand would be testing
		// encoding/json rather than the relay.
		var msg SignalMessage
		if err := decodeSignalMessage(raw, &msg); err != nil {
			return
		}
		msg.From = "0011223344556677"
		msg.Room, msg.PeerID, msg.Error = "", "", ""

		encoded, err := marshalRelayMessage(msg)
		if err != nil {
			return // refused to relay
		}
		if len(encoded) > maxMessageSize {
			t.Fatalf("relayed %d bytes, over the %d limit", len(encoded), maxMessageSize)
		}

		var round SignalMessage
		if err := decodeSignalMessage(encoded, &round); err != nil {
			t.Fatalf("relayed a frame the decoder rejects: %q (%v)", encoded, err)
		}
		if round.Type != msg.Type || round.To != msg.To || round.From != msg.From {
			t.Fatalf("relay changed the envelope: %+v -> %+v", msg, round)
		}

		// Relaying is not a place to grow: a second pass must be a fixed point,
		// or a peer could ratchet a frame upward by bouncing it.
		twice, err := marshalRelayMessage(round)
		if err != nil {
			t.Fatalf("cannot re-relay its own output: %v", err)
		}
		if len(twice) > len(encoded) {
			t.Fatalf("re-encoding grew the frame: %d -> %d", len(encoded), len(twice))
		}
	})
}

// Room codes name a conversation, and the server uses the string it was handed
// as a map key. Anything accepted here has to be exactly one canonical form, or
// two spellings reach the same room while looking like different ones.
func FuzzValidateRoomCode(f *testing.F) {
	for _, seed := range []string{
		"abcdef123456abcdef123456", "ABCDEF123456ABCDEF123456", "",
		"abcdef123456abcdef12345", "abcdef123456abcdef1234567",
		"abcdef123456abcdef12345g", "abcdef123456abcdef12345 ",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, code string) {
		if !ValidateRoomCode(code) {
			return
		}
		if len(code) != RoomCodeHexLen {
			t.Fatalf("accepted %q of length %d", code, len(code))
		}
		for i := 0; i < len(code); i++ {
			c := code[i]
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
			if !isHex {
				t.Fatalf("accepted %q containing %q", code, c)
			}
		}
	})
}
