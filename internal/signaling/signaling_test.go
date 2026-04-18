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

// A joins room
connA.WriteJSON(SignalMessage{Type: "join", Room: "test01"})

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
connB.WriteJSON(SignalMessage{Type: "join", Room: "test01"})
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
