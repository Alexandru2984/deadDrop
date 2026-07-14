package signaling

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"deaddrop/internal/strictjson"

	"github.com/gorilla/websocket"
)

const (
	writeWait                  = 10 * time.Second
	pongWait                   = 60 * time.Second
	pingPeriod                 = (pongWait * 9) / 10
	sessionCheckPeriod         = 5 * time.Second
	maxMessageSize             = 64 * 1024 // 64 KB — SDP offers/answers + ICE are well under this
	joinTimeout                = 15 * time.Second
	signalWindow               = 10 * time.Second
	maxSignalMessagesPerWindow = 120
	maxSignalBytesPerWindow    = 512 * 1024
	maxSignalPayloadText       = 48 * 1024
	sendQueueSize              = 16
)

// AllowedOrigins is set at startup to restrict WebSocket CSRF.
// Only connections from these origins are accepted.
var AllowedOrigins []string

var upgrader = websocket.Upgrader{
	CheckOrigin:      checkOrigin,
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: 10 * time.Second,
}

// checkOrigin validates the Origin header against the allowed list.
// Blocks cross-site WebSocket hijacking (CSRF).
func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Tests can leave AllowedOrigins empty. Once production origins are
		// configured, every client must supply an explicit matching Origin.
		return len(AllowedOrigins) == 0
	}
	for _, allowed := range AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// Peer represents a single WebSocket connection in a room.
type Peer struct {
	ID           string
	room         *Room
	hub          *Hub
	conn         *websocket.Conn
	send         chan []byte
	joinTimer    *time.Timer
	sessionValid func() bool
	closeOnce    sync.Once
	windowAt     time.Time
	windowMsgs   int
	windowBytes  int
	principal    string
}

// ConnectionAccess binds a WebSocket to an authenticated principal and lets the
// pumps re-check that its session has not been revoked.
type ConnectionAccess struct {
	Principal string
	Valid     func() bool
}

// SignalMessage is the envelope for all signaling-layer messages.
type SignalMessage struct {
	Type    string          `json:"type"`
	Room    string          `json:"room,omitempty"`
	PeerID  string          `json:"peerId,omitempty"`
	To      string          `json:"to,omitempty"`
	From    string          `json:"from,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// HandleWebSocket upgrades an HTTP request to a WebSocket and starts read/write
// pumps. Access is mandatory so a new call site cannot accidentally omit live
// session revocation.
func HandleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request, access ConnectionAccess) {
	if access.Valid == nil {
		access.Valid = func() bool { return false }
	}
	if !hub.reserveConnection(access.Principal) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "signaling capacity reached", http.StatusServiceUnavailable)
		return
	}
	reserved := true
	defer func() {
		if reserved {
			hub.releaseConnection(access.Principal)
		}
	}()

	if !access.Valid() {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	peerID, err := generatePeerID()
	if err != nil {
		log.Printf("[ws] peer id generation error: %v", err)
		http.Error(w, "could not create peer", http.StatusInternalServerError)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[ws] upgrade rejected")
		return
	}

	peer := &Peer{
		ID:           peerID,
		hub:          hub,
		conn:         conn,
		send:         make(chan []byte, sendQueueSize),
		sessionValid: access.Valid,
		windowAt:     time.Now(),
		principal:    access.Principal,
	}
	peer.joinTimer = time.AfterFunc(joinTimeout, func() {
		peer.closeWithPolicy("room join timeout")
	})

	// Tell the client its assigned peer ID
	welcome, _ := json.Marshal(SignalMessage{Type: "welcome", PeerID: peer.ID})
	peer.send <- welcome

	reserved = false // readPump owns the slot from this point onward
	go peer.writePump()
	go peer.readPump()
}

// readPump reads messages from the WebSocket and dispatches them.
func (p *Peer) readPump() {
	defer func() {
		p.joinTimer.Stop()
		p.disconnect()
		p.terminate()
		p.hub.releaseConnection(p.principal)
	}()

	p.conn.SetReadLimit(maxMessageSize)
	if err := p.conn.SetReadDeadline(time.Now().Add(pongWait)); err != nil {
		return
	}
	p.conn.SetPongHandler(func(string) error {
		return p.conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		messageType, raw, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage {
			p.closeWithPolicy("text signaling messages required")
			return
		}
		if !p.sessionValid() {
			p.closeWithPolicy("session expired")
			return
		}
		if !p.allowInbound(len(raw)) {
			p.closeWithPolicy("signaling rate limit exceeded")
			return
		}

		var msg SignalMessage
		if err := decodeSignalMessage(raw, &msg); err != nil {
			p.closeWithPolicy("malformed signaling message")
			return
		}
		p.handleMessage(msg)
	}
}

// writePump sends queued messages and periodic pings.
func (p *Peer) writePump() {
	ticker := time.NewTicker(pingPeriod)
	sessionTicker := time.NewTicker(sessionCheckPeriod)
	defer func() {
		ticker.Stop()
		sessionTicker.Stop()
		p.terminate()
	}()

	for {
		select {
		case msg, ok := <-p.send:
			if !p.sessionValid() {
				p.closeWithPolicy("session expired")
				return
			}
			if err := p.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if !ok {
				_ = p.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := p.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			if !p.sessionValid() {
				p.closeWithPolicy("session expired")
				return
			}
			if err := p.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				return
			}
			if err := p.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-sessionTicker.C:
			if !p.sessionValid() {
				p.closeWithPolicy("session expired")
				return
			}
		}
	}
}

func (p *Peer) handleMessage(msg SignalMessage) {
	switch msg.Type {
	case "join":
		if !ValidateRoomCode(msg.Room) || msg.To != "" || msg.From != "" || msg.PeerID != "" || len(msg.Payload) != 0 || msg.Error != "" {
			p.sendError("invalid room code")
			return
		}
		if _, err := p.hub.JoinRoom(msg.Room, p); err != nil {
			p.sendError(err.Error())
			return
		}
		p.joinTimer.Stop()

	case "offer", "answer", "ice-candidate":
		if !p.validRelayMessage(msg) {
			p.sendError("invalid signaling message")
			return
		}
		// Relay WebRTC signaling to the target. The server checks only that the
		// opaque payload is a bounded JSON object; it does not interpret SDP/ICE.
		msg.From = p.ID
		msg.Room, msg.PeerID, msg.Error = "", "", ""
		data, err := marshalRelayMessage(msg)
		if err != nil {
			p.sendError("invalid signaling message")
			return
		}
		if !p.hub.Relay(p, msg.To, data) {
			p.sendError("signaling target unavailable")
		}

	default:
		p.sendError("unsupported signaling message")
	}
}

func (p *Peer) validRelayMessage(msg SignalMessage) bool {
	if p.room == nil || !ValidatePeerID(msg.To) || msg.To == p.ID || msg.Room != "" || msg.From != "" || msg.PeerID != "" || msg.Error != "" {
		return false
	}
	var payload string
	if err := json.Unmarshal(msg.Payload, &payload); err != nil || len(payload) == 0 || len(payload) > maxSignalPayloadText {
		return false
	}
	trimmed := strings.TrimSpace(payload)
	return strings.HasPrefix(trimmed, "{") && json.Valid([]byte(trimmed))
}

func (p *Peer) allowInbound(size int) bool {
	now := time.Now()
	if now.Sub(p.windowAt) >= signalWindow {
		p.windowAt = now
		p.windowMsgs = 0
		p.windowBytes = 0
	}
	p.windowMsgs++
	p.windowBytes += size
	return p.windowMsgs <= maxSignalMessagesPerWindow && p.windowBytes <= maxSignalBytesPerWindow
}

func (p *Peer) sendError(message string) {
	data, _ := json.Marshal(SignalMessage{Type: "error", Error: message})
	if !safeSend(p.send, data) {
		p.terminate()
	}
}

func (p *Peer) closeWithPolicy(reason string) {
	_ = p.conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason),
		time.Now().Add(writeWait),
	)
	p.terminate()
}

func (p *Peer) terminate() {
	p.closeOnce.Do(func() { _ = p.conn.Close() })
}

// disconnect removes this peer from the hub (which notifies other peers).
// All room.Peers access now happens in the Hub goroutine — no data race.
func (p *Peer) disconnect() {
	p.hub.RemovePeer(p)
	close(p.send)
}

// safeSend writes to a bounded channel without blocking. Callers terminate a
// slow consumer on false so critical signaling is never silently dropped.
func safeSend(ch chan []byte, data []byte) (sent bool) {
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	select {
	case ch <- data:
		return true
	default:
		return false
	}
}

func generatePeerID() (string, error) {
	b := make([]byte, PeerIDHexLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func decodeSignalMessage(raw []byte, dst *SignalMessage) error {
	return strictjson.DecodeObject(bytes.NewReader(raw), dst)
}

func marshalRelayMessage(msg SignalMessage) ([]byte, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	// Re-encoding a JSON string can expand escapable characters. Never let an
	// accepted inbound envelope amplify into a larger outbound WebSocket frame.
	if len(data) > maxMessageSize {
		return nil, fmt.Errorf("encoded signaling message exceeds %d bytes", maxMessageSize)
	}
	return data, nil
}
