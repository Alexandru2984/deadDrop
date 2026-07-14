package signaling

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var alwaysValidAccess = ConnectionAccess{Valid: func() bool { return true }}

func TestSignalingFlow(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Start test server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	// Connect Peer A
	connA, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer A dial: %v", err)
	}
	defer connA.Close()

	// Read welcome for A
	var welcomeA SignalMessage
	connA.ReadJSON(&welcomeA)
	if welcomeA.Type != "welcome" || welcomeA.PeerID == "" {
		t.Fatalf("expected welcome, got %+v", welcomeA)
	}
	t.Logf("Peer A = %s", welcomeA.PeerID)

	// A joins a server-shaped 96-bit room.
	connA.WriteJSON(SignalMessage{Type: "join", Room: "abcdef123456abcdef123456"})

	// Connect Peer B
	connB, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("peer B dial: %v", err)
	}
	defer connB.Close()

	var welcomeB SignalMessage
	connB.ReadJSON(&welcomeB)
	if welcomeB.Type != "welcome" || welcomeB.PeerID == "" {
		t.Fatalf("expected welcome, got %+v", welcomeB)
	}
	t.Logf("Peer B = %s", welcomeB.PeerID)

	// B joins same room
	connB.WriteJSON(SignalMessage{Type: "join", Room: "abcdef123456abcdef123456"})
	time.Sleep(100 * time.Millisecond)

	// A should receive peer-joined for B
	var msgA SignalMessage
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	connA.ReadJSON(&msgA)
	if msgA.Type != "peer-joined" || msgA.PeerID != welcomeB.PeerID {
		t.Fatalf("A expected peer-joined(B), got %+v", msgA)
	}

	// B should receive peer-joined for A
	var msgB SignalMessage
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	connB.ReadJSON(&msgB)
	if msgB.Type != "peer-joined" || msgB.PeerID != welcomeA.PeerID {
		t.Fatalf("B expected peer-joined(A), got %+v", msgB)
	}

	// A sends a fake offer to B
	payload, _ := json.Marshal(`{"type":"offer","sdp":"fake"}`)
	offer := SignalMessage{
		Type:    "offer",
		To:      welcomeB.PeerID,
		Payload: payload,
	}
	connA.WriteJSON(offer)
	time.Sleep(100 * time.Millisecond)

	// B should receive the relayed offer with From set
	var relayed SignalMessage
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	connB.ReadJSON(&relayed)
	if relayed.Type != "offer" || relayed.From != welcomeA.PeerID {
		t.Fatalf("B expected offer from A, got %+v", relayed)
	}

	// Close B → A should get peer-left
	connB.Close()
	time.Sleep(200 * time.Millisecond)

	var leftMsg SignalMessage
	connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	connA.ReadJSON(&leftMsg)
	if leftMsg.Type != "peer-left" || leftMsg.PeerID != welcomeB.PeerID {
		t.Fatalf("A expected peer-left(B), got %+v", leftMsg)
	}

	t.Log("✅ Full signaling flow passed")
}

func TestValidateRoomCode(t *testing.T) {
	valid := []string{"abcdef012345abcdef012345", "0123456789abcdef01234567"}
	for _, code := range valid {
		if !ValidateRoomCode(code) {
			t.Errorf("expected %q to be valid", code)
		}
	}

	invalid := []string{
		"", "abc", "ABCDEF012345ABCDEF012345", "abcde!", "hello world",
		"abcdef012345",              // legacy 48-bit code
		"abcdef012345abcdef01234",   // short
		"abcdef012345abcdef0123456", // long
	}
	for _, code := range invalid {
		if ValidateRoomCode(code) {
			t.Errorf("expected %q to be invalid", code)
		}
	}
}

func TestGenerateRoomCode(t *testing.T) {
	code, err := GenerateRoomCode()
	if err != nil {
		t.Fatalf("GenerateRoomCode: %v", err)
	}
	if len(code) != RoomCodeHexLen {
		t.Fatalf("expected %d-char code, got %d: %s", RoomCodeHexLen, len(code), code)
	}
	if !ValidateRoomCode(code) {
		t.Fatalf("generated code %q fails validation", code)
	}

	// Should be unique
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		c, err := GenerateRoomCode()
		if err != nil {
			t.Fatalf("GenerateRoomCode: %v", err)
		}
		if codes[c] {
			t.Fatalf("duplicate code after %d generations: %s", i, c)
		}
		codes[c] = true
	}
}

func TestInvalidRoomCodeRejected(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read welcome
	var welcome SignalMessage
	conn.ReadJSON(&welcome)

	// Try to join with invalid room code
	conn.WriteJSON(SignalMessage{Type: "join", Room: "BAD!"})
	time.Sleep(100 * time.Millisecond)

	var errMsg SignalMessage
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.ReadJSON(&errMsg)
	if errMsg.Type != "error" {
		t.Fatalf("expected error message, got %+v", errMsg)
	}
	if errMsg.Error == "" || errMsg.PeerID != "" {
		t.Fatalf("error must use the error field, got %+v", errMsg)
	}
	t.Log("✅ Invalid room code correctly rejected")
}

func TestRoomPeerLimit(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	roomCode := "aabbccddee01aabbccddee01"
	conns := make([]*websocket.Conn, 0, MaxPeersPerRoom+1)

	// Fill the room to max
	for i := 0; i < MaxPeersPerRoom; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial peer %d: %v", i, err)
		}
		conns = append(conns, conn)

		var welcome SignalMessage
		conn.ReadJSON(&welcome)
		conn.WriteJSON(SignalMessage{Type: "join", Room: roomCode})
		time.Sleep(50 * time.Millisecond)
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()

	// One more should fail
	extraConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial extra peer: %v", err)
	}
	defer extraConn.Close()

	var welcome SignalMessage
	extraConn.ReadJSON(&welcome)
	extraConn.WriteJSON(SignalMessage{Type: "join", Room: roomCode})
	time.Sleep(100 * time.Millisecond)

	var errMsg SignalMessage
	extraConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	extraConn.ReadJSON(&errMsg)
	if errMsg.Type != "error" {
		t.Fatalf("expected error for room full, got %+v", errMsg)
	}
	t.Log("✅ Room peer limit enforced")
}

func TestOriginCheck(t *testing.T) {
	// Set allowed origins
	AllowedOrigins = []string{"https://dead.micutu.com"}

	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	// Connection with allowed origin should work
	header := http.Header{}
	header.Set("Origin", "https://dead.micutu.com")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("expected allowed origin to connect, got: %v", err)
	}
	conn.Close()

	// Connection with disallowed origin should fail
	header.Set("Origin", "https://evil.com")
	_, _, err = websocket.DefaultDialer.Dial(wsURL, header)
	if err == nil {
		t.Fatal("expected disallowed origin to be rejected")
	}

	// Reset for other tests
	AllowedOrigins = nil
	t.Log("✅ Origin check working")
}

func TestOriginCheckRejectsMissingOriginWhenConfigured(t *testing.T) {
	AllowedOrigins = []string{"https://dead.micutu.com"}
	defer func() { AllowedOrigins = nil }()

	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	_, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected missing origin to be rejected")
	}
}

// TestDoubleJoinNoPanic verifies that a peer joining a second room
// properly cleans up the first room, preventing stale references
// that would cause a send-to-closed-channel panic.
func TestDoubleJoinNoPanic(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	// Connect peer A and join room1
	connA, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer connA.Close()
	var welcomeA SignalMessage
	connA.ReadJSON(&welcomeA)
	connA.WriteJSON(SignalMessage{Type: "join", Room: "aabbcc000001aabbcc000001"})
	time.Sleep(100 * time.Millisecond)

	// Connect peer B and join room1 (to observe events)
	connB, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer connB.Close()
	var welcomeB SignalMessage
	connB.ReadJSON(&welcomeB)
	connB.WriteJSON(SignalMessage{Type: "join", Room: "aabbcc000001aabbcc000001"})
	time.Sleep(100 * time.Millisecond)

	// Drain peer-joined notifications
	connA.SetReadDeadline(time.Now().Add(1 * time.Second))
	connA.ReadJSON(&SignalMessage{})
	connB.SetReadDeadline(time.Now().Add(1 * time.Second))
	connB.ReadJSON(&SignalMessage{})

	// A joins a DIFFERENT room — should be removed from room1 first
	connA.WriteJSON(SignalMessage{Type: "join", Room: "aabbcc000002aabbcc000002"})
	time.Sleep(100 * time.Millisecond)

	// B should receive peer-left for A (Hub cleaned up room1)
	var leftMsg SignalMessage
	connB.SetReadDeadline(time.Now().Add(2 * time.Second))
	connB.ReadJSON(&leftMsg)
	if leftMsg.Type != "peer-left" || leftMsg.PeerID != welcomeA.PeerID {
		t.Fatalf("B expected peer-left(A), got %+v", leftMsg)
	}

	// Now disconnect A — this must NOT panic the server
	connA.Close()
	time.Sleep(200 * time.Millisecond)

	// Server is still alive — verify by connecting a new peer
	connC, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("server crashed after double-join disconnect: %v", err)
	}
	defer connC.Close()
	var welcomeC SignalMessage
	connC.ReadJSON(&welcomeC)
	if welcomeC.Type != "welcome" {
		t.Fatalf("expected welcome, got %+v", welcomeC)
	}

	t.Log("✅ Double-join handled safely — no panic")
}

func TestWebSocketMessageSizeLimit(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read welcome
	var welcome SignalMessage
	conn.ReadJSON(&welcome)

	// Send a message larger than maxMessageSize (64 KB) — should disconnect us
	huge := make([]byte, 128*1024)
	for i := range huge {
		huge[i] = 'a'
	}
	// The server may tear the connection down before the write even completes —
	// a write error here is the size limit doing its job, not a test failure.
	if err := conn.WriteMessage(websocket.TextMessage, huge); err != nil {
		t.Log("✅ WebSocket message size limit enforced (connection reset mid-write)")
		return
	}

	// The server should close the connection
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected connection to be closed after oversized message")
	}
	t.Log("✅ WebSocket message size limit enforced")
}

func TestGeneratePeerID(t *testing.T) {
	id, err := generatePeerID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != PeerIDHexLen || !ValidatePeerID(id) {
		t.Fatalf("invalid generated peer ID %q", id)
	}
	for _, invalid := range []string{"", strings.Repeat("a", 16), strings.Repeat("A", PeerIDHexLen), strings.Repeat("g", PeerIDHexLen)} {
		if ValidatePeerID(invalid) {
			t.Errorf("accepted invalid peer ID %q", invalid)
		}
	}
}

func TestDecodeSignalMessageIsStrict(t *testing.T) {
	valid := []byte(`{"type":"join","room":"abcdef012345abcdef012345"}`)
	var msg SignalMessage
	if err := decodeSignalMessage(valid, &msg); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	bad := [][]byte{
		[]byte(`{"type":"join","type":"offer"}`),
		[]byte(`{"type":"join","unknown":true}`),
		[]byte(`{"type":"join"}{"type":"join"}`),
		[]byte(`[]`),
	}
	for _, raw := range bad {
		if err := decodeSignalMessage(raw, &SignalMessage{}); err == nil {
			t.Errorf("accepted malformed envelope %s", raw)
		}
	}
}

func TestMarshaledRelayMessageCannotAmplifyPastLimit(t *testing.T) {
	payload, err := json.Marshal(strings.Repeat("<", maxSignalPayloadText))
	if err != nil {
		t.Fatal(err)
	}
	data, err := marshalRelayMessage(SignalMessage{
		Type: "offer", To: strings.Repeat("a", PeerIDHexLen),
		From: strings.Repeat("b", PeerIDHexLen), Payload: payload,
	})
	if err == nil && len(data) > maxMessageSize {
		t.Fatalf("relay expanded to %d bytes", len(data))
	}
}

func TestHubConnectionCapacityIsBounded(t *testing.T) {
	hub := NewHub()
	for i := 0; i < MaxConnections; i++ {
		if !hub.reserveConnection("") {
			t.Fatalf("slot %d unexpectedly rejected", i)
		}
	}
	if hub.reserveConnection("") {
		t.Fatal("hub accepted a connection beyond its cap")
	}
	for i := 0; i < MaxConnections; i++ {
		hub.releaseConnection("")
	}
	if !hub.reserveConnection("") {
		t.Fatal("released capacity was not reusable")
	}
	hub.releaseConnection("")
	for i := 0; i < MaxConnectionsPerPrincipal; i++ {
		if !hub.reserveConnection("alice") {
			t.Fatalf("principal slot %d unexpectedly rejected", i)
		}
	}
	if hub.reserveConnection("alice") {
		t.Fatal("principal exceeded its connection cap")
	}
	for i := 0; i < MaxConnectionsPerPrincipal; i++ {
		hub.releaseConnection("alice")
	}
}

func TestWebSocketRequiresLiveAccessCheck(t *testing.T) {
	hub := NewHub()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	HandleWebSocket(hub, w, r, ConnectionAccess{})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if got := len(hub.slots); got != 0 {
		t.Fatalf("rejected upgrade leaked %d connection slot(s)", got)
	}
}

func TestFailedRoomMovePreservesMembershipAndRemovalClearsPointer(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	newPeer := func(id string) *Peer {
		return &Peer{ID: id, hub: hub, send: make(chan []byte, sendQueueSize)}
	}
	roomA := "aaaaaaaaaaaaaaaaaaaaaaaa"
	roomB := "bbbbbbbbbbbbbbbbbbbbbbbb"
	mover := newPeer(strings.Repeat("1", PeerIDHexLen))
	original, err := hub.JoinRoom(roomA, mover)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxPeersPerRoom; i++ {
		peer := newPeer(strings.Repeat(string(rune('2'+i)), PeerIDHexLen))
		if _, err := hub.JoinRoom(roomB, peer); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := hub.JoinRoom(roomB, mover); err == nil {
		t.Fatal("move into full room unexpectedly succeeded")
	}
	if mover.room != original || original.Peers[mover.ID] != mover {
		t.Fatal("failed move ejected peer from its original room")
	}
	if _, err := hub.JoinRoom(roomA, mover); err != nil {
		t.Fatalf("duplicate join should be idempotent: %v", err)
	}
	hub.RemovePeer(mover)
	if mover.room != nil {
		t.Fatal("unregister left a stale room pointer")
	}
	if hub.Relay(mover, strings.Repeat("2", PeerIDHexLen), []byte(`{}`)) {
		t.Fatal("unregistered peer relayed through a stale room")
	}
}

func TestInboundSignalingBudget(t *testing.T) {
	p := &Peer{windowAt: time.Now()}
	for i := 0; i < maxSignalMessagesPerWindow; i++ {
		if !p.allowInbound(1) {
			t.Fatalf("message %d rejected before count limit", i)
		}
	}
	if p.allowInbound(1) {
		t.Fatal("message count limit not enforced")
	}
	p = &Peer{windowAt: time.Now()}
	if p.allowInbound(maxSignalBytesPerWindow + 1) {
		t.Fatal("byte budget not enforced")
	}
}

func TestOpenWebSocketIsRevokedWithSession(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	var valid atomic.Bool
	valid.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, ConnectionAccess{Principal: "alice", Valid: valid.Load})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.ReadJSON(&SignalMessage{}); err != nil {
		t.Fatal(err)
	}
	valid.Store(false)
	// Queueing any response makes the writer re-check the captured session
	// immediately; idle sockets are also checked by the periodic timer.
	if err := conn.WriteJSON(SignalMessage{Type: "unsupported"}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("revoked session kept its WebSocket open")
	}
}
