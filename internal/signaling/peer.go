package signaling

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10
)

// AllowedOrigins is set at startup to restrict WebSocket CSRF.
// Only connections from these origins are accepted.
var AllowedOrigins []string

var upgrader = websocket.Upgrader{
	CheckOrigin:     checkOrigin,
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// checkOrigin validates the Origin header against the allowed list.
// Blocks cross-site WebSocket hijacking (CSRF).
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser clients (curl, etc.) don't send Origin — allow for now
		return true
	}
	for _, allowed := range AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	log.Printf("[ws] rejected origin=%s", origin)
	return false
}

// Peer represents a single WebSocket connection in a room.
type Peer struct {
	ID   string
	room *Room
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// SignalMessage is the envelope for all signaling-layer messages.
type SignalMessage struct {
	Type    string          `json:"type"`
	Room    string          `json:"room,omitempty"`
	PeerID  string          `json:"peerId,omitempty"`
	To      string          `json:"to,omitempty"`
	From    string          `json:"from,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// HandleWebSocket upgrades an HTTP request to a WebSocket and starts read/write pumps.
func HandleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade error: %v", err)
		return
	}

	peer := &Peer{
		ID:   generatePeerID(),
		hub:  hub,
		conn: conn,
		send: make(chan []byte, 256),
	}

	// Tell the client its assigned peer ID
	welcome, _ := json.Marshal(SignalMessage{Type: "welcome", PeerID: peer.ID})
	peer.send <- welcome

	go peer.writePump()
	go peer.readPump()
}

// readPump reads messages from the WebSocket and dispatches them.
func (p *Peer) readPump() {
	defer func() {
		p.disconnect()
		p.conn.Close()
	}()

	p.conn.SetReadDeadline(time.Now().Add(pongWait))
	p.conn.SetPongHandler(func(string) error {
		p.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, raw, err := p.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[ws] read error peer=%s: %v", p.ID, err)
			}
			return
		}

		var msg SignalMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			log.Printf("[ws] bad json from peer=%s", p.ID)
			continue
		}
		p.handleMessage(msg)
	}
}

// writePump sends queued messages and periodic pings.
func (p *Peer) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		p.conn.Close()
	}()

	for {
		select {
		case msg, ok := <-p.send:
			p.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				p.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := p.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			p.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := p.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (p *Peer) handleMessage(msg SignalMessage) {
	switch msg.Type {
	case "join":
		if !ValidateRoomCode(msg.Room) {
			errMsg, _ := json.Marshal(SignalMessage{Type: "error", PeerID: "invalid room code"})
			safeSend(p.send, errMsg)
			return
		}
		room, err := p.hub.JoinRoom(msg.Room, p)
		if err != nil {
			errMsg, _ := json.Marshal(SignalMessage{Type: "error", PeerID: err.Error()})
			safeSend(p.send, errMsg)
			return
		}
		log.Printf("[hub] peer=%s joined room=%s", p.ID, room.Code)

	case "offer", "answer", "ice-candidate":
		// Relay WebRTC signaling messages to the target peer via the Hub.
		// The server never inspects the payload — it's opaque signaling data.
		msg.From = p.ID
		data, _ := json.Marshal(msg)
		p.hub.Relay(p, msg.To, data)
	}
}

// disconnect removes this peer from the hub (which notifies other peers).
// All room.Peers access now happens in the Hub goroutine — no data race.
func (p *Peer) disconnect() {
	p.hub.RemovePeer(p)
	close(p.send)
	log.Printf("[ws] peer=%s disconnected", p.ID)
}

// safeSend writes to a channel without blocking (drops message if full).
func safeSend(ch chan []byte, data []byte) {
	select {
	case ch <- data:
	default:
	}
}

func generatePeerID() string {
	b := make([]byte, 8) // 16 hex chars
	rand.Read(b)
	return hex.EncodeToString(b)
}
