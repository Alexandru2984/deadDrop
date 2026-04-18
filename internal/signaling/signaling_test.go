package signaling

import (
"encoding/json"
"net/http"
"net/http/httptest"
"strings"
"testing"
"time"

"github.com/gorilla/websocket"
)

func TestSignalingFlow(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	// Start test server
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r)
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

	// A joins room (must be valid 6-12 hex chars)
	connA.WriteJSON(SignalMessage{Type: "join", Room: "abcdef123456"})

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
	connB.WriteJSON(SignalMessage{Type: "join", Room: "abcdef123456"})
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
	offer := SignalMessage{
		Type:    "offer",
		To:      welcomeB.PeerID,
		Payload: json.RawMessage(`"fake-sdp-offer"`),
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
	valid := []string{"abcdef", "0123456789ab", "aabbcc", "112233445566"}
	for _, code := range valid {
		if !ValidateRoomCode(code) {
			t.Errorf("expected %q to be valid", code)
		}
	}

	invalid := []string{"", "abc", "ABCDEF", "abcde!", "abcdefghijklm", "hello world", "12345"}
	for _, code := range invalid {
		if ValidateRoomCode(code) {
			t.Errorf("expected %q to be invalid", code)
		}
	}
}

func TestGenerateRoomCode(t *testing.T) {
	code := GenerateRoomCode()
	if len(code) != 12 {
		t.Fatalf("expected 12-char code, got %d: %s", len(code), code)
	}
	if !ValidateRoomCode(code) {
		t.Fatalf("generated code %q fails validation", code)
	}

	// Should be unique
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		c := GenerateRoomCode()
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
		HandleWebSocket(hub, w, r)
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
	t.Log("✅ Invalid room code correctly rejected")
}

func TestRoomPeerLimit(t *testing.T) {
	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	roomCode := "aabbccddee01"
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
		HandleWebSocket(hub, w, r)
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
