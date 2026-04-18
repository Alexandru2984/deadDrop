package signaling

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
)

const (
	MaxPeersPerRoom = 10
	MaxRooms        = 1000
)

// Hub manages chat rooms and routes signaling messages between peers.
// Uses channels instead of mutexes for idiomatic Go concurrency.
type Hub struct {
	rooms      map[string]*Room
	register   chan *registerRequest
	unregister chan *unregisterRequest
	relay      chan *relayRequest
}

type Room struct {
	Code  string
	Peers map[string]*Peer
}

type registerRequest struct {
	code     string
	peer     *Peer
	response chan *Room
	err      chan error
}

type unregisterRequest struct {
	peer     *Peer
	done     chan struct{}
}

// relayRequest routes a message to a target peer within a room, safely.
type relayRequest struct {
	from     *Peer
	targetID string
	data     []byte
}

func NewHub() *Hub {
	return &Hub{
		rooms:      make(map[string]*Room),
		register:   make(chan *registerRequest),
		unregister: make(chan *unregisterRequest),
		relay:      make(chan *relayRequest, 256),
	}
}

// Run is the Hub's main event loop — all room state mutations happen here,
// so no locks are needed.
func (h *Hub) Run() {
	for {
		select {
		case req := <-h.register:
			// If peer is already in a room, remove them first to prevent
			// stale references (send-to-closed-channel panic on disconnect).
			if req.peer.room != nil {
				oldRoom := req.peer.room
				delete(oldRoom.Peers, req.peer.ID)
				if len(oldRoom.Peers) == 0 {
					delete(h.rooms, oldRoom.Code)
					log.Printf("[hub] room %s cleaned up", oldRoom.Code)
				} else {
					leftMsg, _ := json.Marshal(SignalMessage{Type: "peer-left", PeerID: req.peer.ID})
					for _, other := range oldRoom.Peers {
						safeSend(other.send, leftMsg)
					}
				}
				req.peer.room = nil
			}

			room, exists := h.rooms[req.code]
			if !exists {
				if len(h.rooms) >= MaxRooms {
					req.response <- nil
					req.err <- fmt.Errorf("server room limit reached")
					continue
				}
				room = &Room{
					Code:  req.code,
					Peers: make(map[string]*Peer),
				}
				h.rooms[req.code] = room
			}
			if len(room.Peers) >= MaxPeersPerRoom {
				req.response <- nil
				req.err <- fmt.Errorf("room is full")
				continue
			}
			room.Peers[req.peer.ID] = req.peer
			req.peer.room = room

			// Notify existing peers about the newcomer, and vice versa
			// Done here in the Hub goroutine where room.Peers is safe to read.
			newPeerMsg, _ := json.Marshal(SignalMessage{Type: "peer-joined", PeerID: req.peer.ID})
			for _, other := range room.Peers {
				if other.ID == req.peer.ID {
					continue
				}
				safeSend(other.send, newPeerMsg)
				existingMsg, _ := json.Marshal(SignalMessage{Type: "peer-joined", PeerID: other.ID})
				safeSend(req.peer.send, existingMsg)
			}

			req.response <- room
			req.err <- nil

		case req := <-h.unregister:
			peer := req.peer
			if peer.room != nil {
				room := peer.room
				// Notify other peers about the departure (safe — we're in the Hub goroutine)
				leftMsg, _ := json.Marshal(SignalMessage{Type: "peer-left", PeerID: peer.ID})
				for _, other := range room.Peers {
					if other.ID != peer.ID {
						safeSend(other.send, leftMsg)
					}
				}
				delete(room.Peers, peer.ID)
				if len(room.Peers) == 0 {
					delete(h.rooms, room.Code)
					log.Printf("[hub] room %s cleaned up", room.Code)
				}
			}
			close(req.done)

		case req := <-h.relay:
			// Relay signaling messages (offer/answer/ice) safely through the Hub
			if req.from.room == nil {
				continue
			}
			if target, ok := req.from.room.Peers[req.targetID]; ok {
				safeSend(target.send, req.data)
			}
		}
	}
}

// JoinRoom adds a peer to a room (creates if needed). Thread-safe via channel.
// Peer notifications are now sent from the Hub goroutine (no race).
// Returns an error if the room is full or the server hit its room limit.
func (h *Hub) JoinRoom(code string, peer *Peer) (*Room, error) {
	resp := make(chan *Room, 1)
	errCh := make(chan error, 1)
	h.register <- &registerRequest{code: code, peer: peer, response: resp, err: errCh}
	room := <-resp
	err := <-errCh
	return room, err
}

// RemovePeer removes a peer from their room and notifies others. Thread-safe via channel.
// Blocks until removal is complete to ensure send channel is closed after.
func (h *Hub) RemovePeer(peer *Peer) {
	done := make(chan struct{})
	h.unregister <- &unregisterRequest{peer: peer, done: done}
	<-done
}

// Relay routes a signaling message to a target peer within the sender's room.
// Thread-safe via channel — avoids reading room.Peers from the readPump goroutine.
func (h *Hub) Relay(from *Peer, targetID string, data []byte) {
	h.relay <- &relayRequest{from: from, targetID: targetID, data: data}
}

func GenerateRoomCode() string {
	b := make([]byte, 6) // produces 12 hex characters (~281 trillion combinations)
	if _, err := rand.Read(b); err != nil {
		log.Printf("[hub] crypto/rand error: %v", err)
	}
	return hex.EncodeToString(b)
}

// ValidateRoomCode checks that a room code is 6-12 hex characters.
func ValidateRoomCode(code string) bool {
	if len(code) < 6 || len(code) > 12 {
		return false
	}
	for _, c := range code {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
