package signaling

import (
	"crypto/rand"
	"encoding/hex"
	"log"
)

// Hub manages chat rooms and routes signaling messages between peers.
// Uses channels instead of mutexes for idiomatic Go concurrency.
type Hub struct {
	rooms      map[string]*Room
	register   chan *registerRequest
	unregister chan *Peer
}

type Room struct {
	Code  string
	Peers map[string]*Peer
}

type registerRequest struct {
	code     string
	peer     *Peer
	response chan *Room
}

func NewHub() *Hub {
	return &Hub{
		rooms:      make(map[string]*Room),
		register:   make(chan *registerRequest),
		unregister: make(chan *Peer),
	}
}

// Run is the Hub's main event loop — all room state mutations happen here,
// so no locks are needed.
func (h *Hub) Run() {
	for {
		select {
		case req := <-h.register:
			room, exists := h.rooms[req.code]
			if !exists {
				room = &Room{
					Code:  req.code,
					Peers: make(map[string]*Peer),
				}
				h.rooms[req.code] = room
			}
			room.Peers[req.peer.ID] = req.peer
			req.peer.room = room
			req.response <- room

		case peer := <-h.unregister:
			if peer.room == nil {
				continue
			}
			room := peer.room
			delete(room.Peers, peer.ID)
			// Clean up empty rooms to avoid leaks
			if len(room.Peers) == 0 {
				delete(h.rooms, room.Code)
				log.Printf("[hub] room %s cleaned up", room.Code)
			}
		}
	}
}

// JoinRoom adds a peer to a room (creates if needed). Thread-safe via channel.
func (h *Hub) JoinRoom(code string, peer *Peer) *Room {
	resp := make(chan *Room, 1)
	h.register <- &registerRequest{code: code, peer: peer, response: resp}
	return <-resp
}

// RemovePeer removes a peer from their room. Thread-safe via channel.
func (h *Hub) RemovePeer(peer *Peer) {
	h.unregister <- peer
}

func GenerateRoomCode() string {
	b := make([]byte, 3) // produces 6 hex characters
	if _, err := rand.Read(b); err != nil {
		log.Printf("[hub] crypto/rand error: %v", err)
	}
	return hex.EncodeToString(b)
}
